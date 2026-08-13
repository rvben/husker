# ADR-0008: Daemon Runtime Supervision

- Status: Accepted
- Date: 2026-08-13

## Context

Each platform branch assembled a `HuskerCore`, spawned background tasks, served
the API, and drained VMs independently. The tasks were detached and had no
shutdown input. A server bind or serving error returned before VM drain, and on
Linux also returned before NAT and bridge cleanup. Linux auto-resume listeners
could additionally wake a suspended VM after draining had begun.

Backend construction and host networking cannot be flattened into one generic
platform abstraction: ADR-0001 intentionally keeps Linux bridge/nftables and
macOS VZ networking explicit, while ADR-0005 records backend-specific guest
shutdown behavior.

## Decision

- The daemon runtime starts only after a platform branch has assembled its
  `HuskerCore`. Backend construction and host-network setup/teardown remain in
  the platform branch.
- The runtime has two closed modes: `Basic` and `LinuxNet`. The Linux mode adds
  port-forward recovery, resume-listener recovery, reclaim, and idle-policy
  work without exposing independent booleans for invalid combinations.
- Every spawned worker is owned by the runtime. Periodic mutating workers share
  a watch-channel shutdown signal and are joined before VM drain. A five-second
  bound aborts a worker that cannot stop cooperatively. The read-only metrics
  endpoint is then aborted and joined.
- After serving ends for either success or failure, the runtime stops workers,
  closes auto-resume ingress without servicing queued connections, and drains
  running or paused VMs. It then returns the original serving result.
- A Firecracker stop is complete only after the VMM process exits. The backend
  waits up to five seconds after `SendCtrlAltDel`, then force-kills and reaps the
  process so host resources are no longer held when cleanup begins.
- On Linux, shutdown immediately releases the TAP, IP, and forwarding state of
  terminal VMs after drain. The normal grace period for inspecting a recently
  stopped VM remains unchanged during ordinary daemon operation.
- Suspended VMs preserve their TAP and network identity across shutdown. On
  startup, the runtime reattaches every preserved TAP to the newly created host
  bridge before it restores forwarding listeners or serves health/API traffic.
  Failure to reattach is a startup failure, not a degraded green daemon.
- Snapshot suspend clears the destroyed VMM's PID from state; snapshot restore
  atomically persists `running` with the replacement VMM PID returned by the
  backend.
- Linux cgroup initialization happens before bridge creation. After a bridge is
  created, every later result flows through both NAT cleanup and bridge deletion.
  A runtime error remains primary; otherwise a cleanup failure is returned.

## Consequences

- Reconciliation cannot create or mutate VMs concurrently with shutdown drain.
- A bind or serving failure still drains VMs and releases Linux host networking.
- Suspended VMs cannot auto-resume through a forwarded connection during drain.
- Shutdown ordering and failure precedence are testable through the runtime
  interface without installing operating-system signal handlers.
- A privileged Linux drill exercises a post-network API bind failure, empty
  SIGTERM, a live-Firecracker SIGTERM, and suspend -> daemon restart -> first
  forwarded connection. It asserts worker/drain/cleanup ordering, VMM exit,
  persisted stopped state, suspended-TAP reattachment, replacement-PID
  persistence, end-to-end echo after auto-resume, and the absence of leaked TAP,
  bridge, nftables, and metrics resources. The live-VM scenarios are mandatory
  on the nightly self-hosted KVM runner.
- Platform networking remains explicit and consistent with ADR-0001 and
  ADR-0005.
