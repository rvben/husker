# Security Policy

## Reporting a vulnerability

Report security vulnerabilities privately via GitHub Security Advisories:
<https://github.com/rvben/husker/security/advisories/new>

Do not open public issues for security reports. Expect an initial response within 72 hours.

## Supported versions

Only the latest `0.x` release receives security fixes. Pre-1.0 releases do not guarantee backwards compatibility across patch versions.

## Scope

In scope:

- `husker` daemon and CLI (`crates/husker`, `crates/husker-api`, `crates/husker-core`)
- Guest agent protocol and host-guest channel (`crates/husker-agent`, `crates/husker-agent-proto`)
- Host networking and port-forward path (`crates/husker-net`, Linux)
- Default image build pipeline (`.github/workflows/build-images.yml`, `guest/`)

Out of scope:

- Guest kernel or rootfs CVEs (report upstream to Alpine / the kernel project).
- Firecracker vulnerabilities (report to [firecracker-microvm](https://github.com/firecracker-microvm/firecracker)).
- Apple Virtualization.framework vulnerabilities (report to Apple).

## See also

- [Threat model](docs/security/threat-model.md) — STRIDE analysis and residual risk.
- [Hardening guide](docs/security/hardening-guide.md) — recommended deployment posture.
