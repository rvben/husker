# ADR-0005: Guest Shutdown Semantics Per Backend

- Status: Accepted
- Date: 2026-07-02

## Context

Ephemeral and self-terminating guests need to exit their VMM process cleanly so
the host can detect exit and reclaim resources. The behavior of guest-issued
`poweroff`/`reboot` differs by backend, verified on real hosts:

- **Firecracker:** guest `reboot -f` exits the VM process; `poweroff -f` merely
  HALTS (no ACPI) and strands the VM.
- **QEMU:** the opposite - guest `poweroff -f` exits the process; `reboot`
  reboots in place.
- **Apple VZ:** `poweroff -f` stops the VM; `reboot -f` is a no-op on the
  aarch64 Alpine guest.

## Decision

- Ephemeral/self-terminating guests use `reboot` on Firecracker and `poweroff`
  on QEMU/VZ.
- Runtime liveness (v0.4.1+) marks exited VMs stopped via refreshed reads, and
  the reconciler replaces service instances.

## Consequences

- Guest-exit detection is reliable per backend.
- Any new backend must document its guest-shutdown behavior here before shipping
  self-terminating-guest features.
