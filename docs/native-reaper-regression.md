# Linux native-reaper regression check

`make test-factory-native-reaper-gated` skips unless
`HUSKER_RUN_FACTORY_NATIVE_REAPER_E2E=1`. It is deliberately excluded from
scheduled and pull-request privileged workflows. `make test-sdk` covers the
command's nonprivileged safety gates.

An opted-in run creates one private loopback daemon and submits one offline
factory lifecycle job. After the probe reports readiness, the controller sends
SIGKILL through a pidfd to **only the daemon**. The original Firecracker must
remain alive with its KVM descriptors for at least three seconds. Restart must
produce the exact native-reaper confirmation for that PID and job, followed by
pidfd-confirmed exit. A missing process alone cannot pass.

The existing `factory_restart_e2e.py inspect` verifies the original job/session/
generation/specification identity, exact journaled output, terminal `unknown`
outcome and confirmed destruction. The controller additionally checks zero VM
rows, creation leases and generation files, exactly one job submission, and
GET-only API requests after restart. It stops the fixture and checks its entire
cgroup is empty, its bridge removed, host firewall unchanged, and other Husker/
VMM process identities unchanged. `result.json` is written only after recovery
and the final host audit pass. This proves this Linux recovery scenario; it does
not prove job resumption, outcome promotion, macOS recovery, or power-loss safety.

## Prepare an immutable bundle

Use a dedicated, otherwise quiescent Linux test host with systemd, cgroup v2,
KVM, Firecracker, `ip`, `nft`, `ss`, and Python 3.11+. Allow at least 64 GiB free
**after** staging. Do not run against a production daemon or share this test's
network/CID ranges with concurrently starting daemons. No downloads, builds or
service installations are performed by this check.

Assemble a new bundle from five **prebuilt, pinned local artifacts**. The
preparation command needs Git and Python on Linux or macOS, but no root, KVM,
network access, daemon or filesystem mounts. It copies the supplied rootfs;
it does not compile binaries, build a rootfs, install tools, or resolve versions.

Write a version-one JSON plan with these exact keys (replace paths, digests and
the full declared daemon build commit with reviewed values):

```json
{
  "version": 1,
  "daemon_build_revision": "0123456789abcdef0123456789abcdef01234567",
  "inputs": {
    "daemon": {"path": "/staged/husker", "digest": "sha256:DAEMON_SHA256"},
    "firecracker": {"path": "/staged/firecracker", "digest": "sha256:FIRECRACKER_SHA256"},
    "probe": {"path": "/staged/factory-lifecycle-probe", "digest": "sha256:PROBE_SHA256"},
    "kernel": {"path": "/staged/vmlinux", "digest": "sha256:KERNEL_SHA256"},
    "rootfs": {"path": "/staged/rootfs.ext4", "digest": "sha256:ROOTFS_SHA256"}
  }
}
```

Every digest is `sha256:` followed by 64 lowercase hexadecimal digits. Inputs
must be independent regular files, with no symlink in the final component or
hardlinks. Binary/kernel headers must identify little-endian x86_64 ELF64;
the rootfs must have an ext4 superblock and be at most 8 GiB. These are format
checks, not proof that the guest can boot.

The daemon must have its guest agent embedded. Supply a compatible Firecracker,
a probe compiled from `guest/factory/lifecycle-probe.c`, a Firecracker-compatible
kernel, and an already prepared factory rootfs containing the matching agent,
job runner and factory init. Use the existing guest image/build tooling for
those artifacts. This command records their reviewed pins, not their build
provenance. It never invokes an input executable.

From the source checkout whose SDK/controller you want to freeze:

```sh
python3 scripts/prepare_factory_native_reaper.py \
  --plan /staged/reaper-plan.json --output /var/tmp/reaper-bundle
```

The output must not exist. Its parent must be an absolute canonical directory
(use the real `/private/...` path on macOS). The command:

- Copies each artifact into private storage while checking its expected hash,
  size bound and file identity, then seals the copy read-only.
- Generates canonical FrozenBundle v1 `inputs/source.tar` and
  `inputs/acceptance.tar` from the frozen probe and sentinel. Checks exact
  header encoding, file modes and padding before any API submission; ordinary
  Python/system tar archives are not interchangeable with this wire format.
- Freezes the SDK/controller and records the checkout's Git revision, relevant
  dirty-source status, source-file hashes, and artifact hashes/sizes in
  `preparation.json`. Source changes during assembly fail the preparation.
- Binds that receipt into a version-two `manifest.json` and verifies the whole
  bundle. The same unchanged source and artifacts produce identical manifests
  across different output locations.

The supplied daemon's `daemon_build_revision` is explicitly a declaration:
`daemon_build_revision_verified` remains `false`. The checkout revision describes
preparation/support code. It does not prove which source produced a prebuilt
binary. `runtime_verified` and `hermetic_build` also remain `false`. A dirty
checkout is recorded as such with exact relevant file hashes; use a clean checkout
for a bundle reproducible from its recorded Git commit. The `source_files_clean`
flag covers the preparation/support files listed in the receipt.

Save the printed manifest `sha256`. Failed assembly removes only its newly
created output; an existing output is never adopted or overwritten. The helper
copies whole rootfs contents, so budget for the output's full disk size.
Transfer the complete bundle to the test host if necessary. Before privileged
execution, make it and all its contents root-owned, retain its `0700` root
permissions, and prohibit group/other writes. Executables already have mode
`0500`. Do not modify inputs after preparation.

Verify using the frozen controller and the saved digest:

```sh
sudo python3 /var/tmp/reaper-bundle/support/scripts/ci/factory_native_reaper_e2e.py \
  verify --bundle /var/tmp/reaper-bundle --sha256 MANIFEST_SHA256
```

The older `factory_native_reaper_e2e.py prepare --bundle ...` mode still accepts
a manually staged directory and emits a version-one manifest. The verifier
supports both versions; new version-two receipts are hashed as required inputs.

## Run once

Explicit operator approval is required for this privileged fault injection.
After approval, run the frozen controller:

```sh
sudo env HUSKER_RUN_FACTORY_NATIVE_REAPER_E2E=1 \
  python3 /var/tmp/reaper-bundle/support/scripts/ci/factory_native_reaper_e2e.py \
  run --bundle /var/tmp/reaper-bundle --sha256 MANIFEST_SHA256 \
  --port 19132 --subnet 172.30.81.0/24 --cid 34000
```

The command checks listener, bridge, subnet-route and active Husker allocator
conflicts before creating a daemon or submitting a job. It uses random private
unit/bridge names and a host lock to serialize these checks. `control/` is created
exclusively: every started or uncertain attempt consumes its bundle. Never delete
that directory to retry, or repeat a POST after lost acknowledgement. Retain the
journal and inspect the original execution read-only instead.

The controller runs in a separate systemd unit and survives SSH disconnection.
Its independent watchdog holds an open descriptor to the exact fixture cgroup;
after 750 seconds it kills only that subtree. Fixture limits are 2 GiB/200% CPU,
one guest vCPU/512 MiB RAM/8 GiB disk; the daemon's runtime is capped at 900 seconds.
The controller disarms the watchdog only after every descendant exits, including
unexpected helpers. If the watchdog fires, it checks for exit for up to 15 seconds;
a timeout remains a failure requiring a host audit. A watchdog trigger or emergency kill fails the proof. If the controller
is forcibly terminated, the watchdog bounds surviving processes; bridge, disk and
firewall cleanup still need an ownership-based audit. Never infer complete cleanup
from process death or remove unrelated resources.

To permit systemd to start a replacement daemon while the VMM survives, the
controller temporarily disables only the fixture root's **child** CPU/memory
controllers. The unit's own hard CPU/memory caps, cgroup inode, and VM cgroup inode
must remain unchanged. This fixture accommodation is recorded separately and is
not a change to installed service configuration.

Evidence stays in `control/evidence/`, including the original journal, daemon log,
survival samples, native-reaper confirmation, recovery receipt and final audit.
The token and configuration remain private; do not upload the whole bundle or
configuration as CI artifacts. Review specific evidence files before sharing.
