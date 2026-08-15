# Case study: a two-host homelab execution plane

This case study records a real Husker deployment and the evidence available on
2026-08-15. It is not a scale benchmark or a production-readiness claim. It is
a set of repeatable patterns for moving risky, bursty, or automation-oriented
work away from laptops and long-lived service hosts.

## The deployment

The homelab keeps its stateful services on Proxmox and gives execution work to
two Husker hosts with different trust boundaries:

| Host | Shape | Trust boundary | Workloads |
|---|---|---|---|
| `husker01` | Bare-metal Intel N100, 4 cores, 16 GiB RAM, XFS/reflink storage | Untrusted guests can use DNS and the internet but cannot initiate connections to the host, LAN, or private VLANs | Remote development sandboxes, risky agent commands, Rust builds |
| `husker-dev` | Nested KVM VM, 4 vCPU, 8 GiB RAM, XFS/reflink data disk | Trusted execution plane with access to internal developer services | Ephemeral GitHub Actions runner, scheduled GitHub-to-Gitea mirroring, Husker integration work |

This split is more important than host count. A job needing private registry or
Gitea access belongs on the trusted plane. Code that may be malicious or simply
unpredictable belongs on the isolated plane. Long-lived databases, monitoring,
and ingress remain outside both.

Both hosts are provisioned by Ansible, expose Husker metrics to Prometheus, and
are checked for daemon reachability, failed diagnostics, and failed VMs. Fleet
verification compares the installed binary hash—not only its version string—to
the pinned release artifact.

## Workloads with measured value

### 1. Offloading a memory-heavy application build

A release build for a Rust application originally ran inside its 2 GiB service
LXC. Thin LTO exhausted the cgroup, starved the hypervisor and tailnet, and made
the place serving the application responsible for compiling its replacement.

The build now runs in a throwaway QEMU/KVM guest on `husker01` with 4 vCPU and
8 GiB RAM. The source is shared from a dedicated allowlisted host directory,
and a declarative 20 GiB `lifeos-build` volume preserves the expensive build
tree. A warm release build takes about 3 minutes 45 seconds and produces an
approximately 31 MiB artifact. Deployment verifies its SHA-256 and target glibc
before replacement; rollback stays outside the guest.

Why Husker helps:

- the compiler cannot consume the service container's memory;
- the build environment is reproducible and disposable;
- source sharing avoids repeatedly copying a large tree;
- the persistent volume retains build acceleration without retaining the VM;
- artifact validation keeps the guest outside the deployment trust boundary.

For smaller trees, `husker job --sync-cwd --out ...` provides the same clean-room
shape without a host mount. Large workspace archives are uploaded in chunks, so
the file API no longer imposes a roughly 1 MiB practical ceiling on this path.

That large-workspace path was exercised against the released fleet, not only in
unit tests. After deploying `v0.4.44`, a temporary Git repository containing one
tracked 3 MiB random file was synced from the Mac to `husker01`. A reference gzip
archive of the payload was 3,146,884 bytes, forcing multiple 512 KiB writes. The
guest's SHA-256 matched the host exactly:

```text
36cf91cd38e93717947e3d86ea6b69751a553525c6791163c28b5dcf5b178ab3
```

The ephemeral job exited `0` in 2.48 seconds wall time, and the subsequent VM
list contained zero items. At the time of the proof, both hosts' installed
`husker 0.4.44` binary matched the release artifact SHA-256
`60a8df575832f18a08a133c54109b9bcdc07a17eb0dbc4d7461029fa1b675930`.

### 2. A self-replacing CI runner

`husker-dev` runs a reconciler-managed service with desired size one. Its guest
registers as a single-use, ephemeral GitHub Actions runner, executes one job,
then exits. Husker replaces it with a fresh VM. A host-side token broker holds
the repository administration credential; the guest receives only a short-lived
registration token.

At the 2026-08-15 observation point:

- desired and current service size were both `1`;
- the runner was online;
- the seven visible `husker smoke` workflow runs had succeeded;
- the latest inspected workflow completed on the Husker runner in 2 minutes.

This is a good fit when runner cleanliness and containment matter more than
maximum throughput. It is not yet evidence for a large concurrent fleet.

### 3. Scheduled automation in a clean room

A systemd timer invokes `husker job --sync-cwd` daily to mirror repositories
from GitHub to Gitea. API tokens are read from a root-only env file and sent to
the guest without appearing in the host command line. The VM installs its small
runtime dependency, performs the idempotent sync, and is destroyed.

On 2026-08-15 the timer's most recent run had completed successfully and its
next run was scheduled. This pattern is useful for maintenance scripts that
need network access and secrets but do not deserve a permanent container or a
long-lived mutable Python environment.

### 4. Remote disposable sandboxes

The Mac uses an SSH-backed Husker context to start jobs on `husker01`. Cold guest
uptime at first command was measured at 0.58–0.61 seconds across the deployed
catalog images; end-to-end wall time was about 2 seconds and includes SSH,
copy-on-write clone setup, VMM startup, and teardown. Reflink clone cost stayed
flat across images from 0.32 to 2.21 GB.

The isolation policy was exercised rather than only inspected: guests retained
public internet and DNS access, while host SSH, LAN services, and Gitea on the
private VLAN were blocked. Source-address spoofing did not bypass the rule, and
an inbound port forward still reached a guest.

This is the strongest day-to-day use case: move commands that are risky to the
laptop, dependency-heavy, or likely to leave residue into a VM that disappears.

## Reusable operating patterns

### Pick the trust plane explicitly

| Requirement | Recommended placement |
|---|---|
| Public dependencies only; repository or agent output is not trusted | Isolated bare-metal host with guest LAN/host denial |
| Private registry, Gitea, staging systems, or internal test fixtures | Trusted Husker host on the developer network |
| Durable database, ingress, monitoring, or backup source of truth | Existing long-lived service platform, not a job VM |
| ARM-specific build or test | Native ARM builder until the Husker guest-agent path supports that target fully |

Do not weaken the isolated host's network policy for one convenient build. Route
that workload to the trusted plane instead.

### Keep durability narrow

Use a throwaway rootfs for the job and make persistence an explicit choice:

- `--out` for selected artifacts;
- `--write-back` for intentional source changes;
- `--volume` for sequential caches or build trees;
- `--mount` for a dedicated allowlisted workspace that needs live sharing.

Persistent volumes are single-writer resources. Do not attach one ext4 volume
to concurrent guests.

### Keep secrets out of argv

Prefer daemon-stored secrets where the deployment supports them. For a root-only
host file, use `--env-file` rather than expanding values into `-e KEY="$VALUE"`:

```sh
husker job python:3.12-alpine \
  --env-file /etc/my-job/config \
  --sync-cwd -- python3 task.py
```

The client reads the file and transfers the values to the daemon, while `ps` and
shell history show only the file path.

### Make proof part of operations

For every recurring workload, retain enough bounded evidence to answer:

- Did it run, succeed, and produce the expected artifact or external change?
- How long did guest boot and total work take?
- Did the VM disappear or get replaced afterward?
- Did the job stay within its CPU, memory, filesystem, and network boundary?
- Can the fleet reproduce the same binary and image/agent versions?

In this deployment, systemd history proves scheduled-job outcomes, GitHub proves
runner outcomes, SHA-256 and target validation prove release artifacts, and
Prometheus/Grafana cover the daemon and host. Husker itself still needs bounded
job success and duration metrics to make this evidence available from one place.

## Highest-value next steps

The deployment points to a practical order for further work:

1. Add daemon-side job outcome, boot-duration, execution-duration, cleanup, and
   service-replacement metrics with bounded labels.
2. Add aggregate memory admission control, not only per-VM cgroup limits, so two
   individually valid jobs cannot overcommit a small host.
3. Exercise restore procedures for persistent volumes and catalog images, then
   automate those drills.
4. Add a trusted Gitea Actions runner if local CI demand justifies another
   reconciler-managed service.
5. Integrate Firecracker's jailer only after its filesystem, cgroup, networking,
   cleanup, and upgrade lifecycle are designed and tested end to end.

The first four workloads above are useful today. The next steps are about making
their value easier to measure and their failure modes safer, not inventing a new
reason to deploy Husker.
