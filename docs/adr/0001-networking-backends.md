# ADR-0001: Networking Backend Strategy

- Status: Accepted
- Date: 2026-02-16

## Context

Husker supports Linux Firecracker and macOS Virtualization.framework. Host networking semantics differ across platforms.

## Decision

- Linux:
  - bridge + TAP + nftables NAT in `husker-net`
  - explicit host port forwarding support
- macOS:
  - rely on VZ-managed shared NAT
  - no inbound host port mapping support

## Consequences

- Platform-specific behavior is explicit and documented.
- API exposes Linux-only port-forward endpoints/tags.
- CLI keeps feature-gated port-forward behavior with clear errors on unsupported platforms.
