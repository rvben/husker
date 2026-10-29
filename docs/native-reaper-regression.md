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

Stage independent regular files under an absolute private `0700` directory:

| Bundle path | Input |
| --- | --- |
| `bin/husker` | Linux daemon built from the revision under test, with guest agent embedded |
| `bin/firecracker` | Compatible Firecracker executable |
| `bin/factory-lifecycle-probe` | Probe built from `guest/factory/lifecycle_probe.c` |
| `prepared/vmlinux` | Firecracker-compatible kernel |
| `prepared/rootfs.ext4` | Prepared factory rootfs, at most 8 GiB, with matching agent, job runner and factory init |
| `inputs/source.tar` | Frozen lifecycle probe and `frozen-sentinel` payload |
| `inputs/acceptance.tar` | Frozen `frozen-sentinel` acceptance payload |

Use the existing factory preparation/lifecycle tooling to produce those guest
inputs. The harness validates the exact payload contents before any API POST.
The bundle is trusted executable input: review its provenance, including the
rootfs and daemon build, before activation. A digest records identity; it does
not establish provenance.

From the source revision under test, freeze the SDK, harness and controller and
record every file's SHA-256:

```sh
python3 scripts/ci/factory_native_reaper_e2e.py prepare --bundle /var/tmp/reaper-bundle
```

Save the printed manifest `sha256`. Preparation does not start anything and
refuses a previously prepared bundle. Transfer the complete bundle to the test
host if necessary. Before privileged execution, make the bundle and all its
contents root-owned, keep the root directory `0700`, prohibit group/other writes,
and make `bin/husker` and `bin/firecracker` executable. Do not modify inputs after
preparation.

Verify using the frozen controller and the saved digest:

```sh
sudo python3 /var/tmp/reaper-bundle/support/scripts/ci/factory_native_reaper_e2e.py \
  verify --bundle /var/tmp/reaper-bundle --sha256 MANIFEST_SHA256
```

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
