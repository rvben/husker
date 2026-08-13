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
- Linux cgroup initialization happens before bridge creation. After a bridge is
  created, every later result flows through both NAT cleanup and bridge deletion.
  A runtime error remains primary; otherwise a cleanup failure is returned.

## Consequences

- Reconciliation cannot create or mutate VMs concurrently with shutdown drain.
- A bind or serving failure still drains VMs and releases Linux host networking.
- Suspended VMs cannot auto-resume through a forwarded connection during drain.
- Shutdown ordering and failure precedence are testable through the runtime
  interface without installing operating-system signal handlers.
- A privileged Linux drill exercises both a post-network API bind failure and
  SIGTERM, asserting worker/drain/cleanup ordering and the absence of leaked
  bridge, nftables, and metrics resources. It runs nightly on the isolated
  self-hosted E2E runner.
- Platform networking remains explicit and consistent with ADR-0001 and
  ADR-0005.
