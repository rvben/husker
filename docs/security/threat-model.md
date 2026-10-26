# Threat Model (STRIDE)

Last updated: 2026-10-26

## Scope

- Daemon API (`crates/husker-api`)
- Core lifecycle/state engine (`crates/husker-core`, `crates/husker-state`)
- Guest agent channel (`crates/husker-agent`, `crates/husker-agent-proto`)
- Host networking and port-forward path (`crates/husker-net`, Linux only)

## Assets

- Host integrity (process control, nftables rules, filesystem)
- VM isolation boundaries and lifecycle state
- Guest command/file execution channels
- API credentials and audit trail
- Persistent state (SQLite and runtime files)

## STRIDE analysis

| Category | Threat | Current control(s) | Validation |
|---|---|---|---|
| Spoofing | Unauthorized API caller invokes mutating endpoints | Deny-by-default bearer auth (only `/v1/health` + static docs are unauthenticated); loopback-only default bind, and a non-loopback bind refuses to start without a token | `cargo test -p husker-api` auth middleware tests |
| Tampering | Guest file operations target unsafe paths | Path normalization + optional read/write allowlists | API integration tests for policy denial |
| Tampering / Information Disclosure | Authenticated caller names host files (VM images and kernels, image import/export, `--mount` hosts) | The daemon's OS identity and filesystem permissions are the boundary (ADR-0009); format validation on images and kernels; import/export/mount paths must be absolute, free of `..` and not end in a symlink; export never overwrites; mounts require the deny-by-default `allowed_mount_host_paths` opt-in | `husker-core` host-path and mount-spec tests; `husker-api` mount allowlist tests |
| Repudiation | Sensitive actions not attributable | Structured audit logs for `exec`, file read/write, shell start/exit; request ID propagation | API unit/integration tests + log schema checks |
| Information Disclosure | Excessive file read payload leaks data | Read-size policy limits; explicit policy error code | API integration tests |
| Denial of Service | Abuse via shell/exec/files endpoints | Sliding-window per-client rate limit on sensitive routes; request body max limit | Rate-limit middleware tests (429 path) |
| Elevation of Privilege | Dangerous guest commands or env injection | Exec allow/deny policy, env allowlist, timeout | Exec policy tests in API crate |
| Tampering/DoS | State/network drift after crash/restart | Startup reconciliation of persisted port forwards; idempotent lifecycle ops | Core startup reconciliation + lifecycle tests |
| Spoofing / Elevation of Privilege | A guest's outbound connection on a forwarded port, or transit traffic the host routes for another network, is rewritten by a port forward's DNAT rule | The DNAT rule matches only packets that enter from outside the guest bridge and are addressed to a host-local address (`iifname != <bridge>`, `fib daddr type local`) | `husker-net` port-forward rule unit tests; bridge E2E |

## Residual risk

- Application authentication is a shared bearer token. Transport TLS and
  optional client-certificate authentication are deliberately delegated to a
  loopback-connected reverse proxy or private service mesh (ADR-0002); never
  send the token over plaintext across an untrusted network.
- **No multi-tenancy.** The daemon has a single shared bearer token, not
  per-caller principals. Every authenticated caller has full, unrestricted
  access to every VM, secret, and volume on the daemon, regardless of who
  created it - there is no per-caller ownership or isolation. Sharing one daemon
  between mutually-distrusting users is therefore NOT supported. Run a daemon per
  trust domain.
- A remotely-bound daemon (`--allow-remote`) now refuses to start without an
  `api_token`, and with a token configured every route except `/v1/health` and
  the static API docs requires it (reads included). A blank token is refused at
  start-up rather than accepted as a configured one.
- A loopback bind without a token is open to every local account on the host.
  The daemon cannot distinguish local users over TCP and does not attempt to
  (ADR-0002); on shared hosts, set `api_token` even for loopback.
- Host paths named in requests (images, kernels, import sources, export
  destinations, mount hosts) are trusted operator input within the daemon's
  trust domain. The daemon's own user and filesystem permissions bound what it
  can read or write; the in-daemon checks (absolute, no `..`, no trailing
  symlink, format validation, the lexical mount allowlist) guard against
  mistakes, not against a hostile token holder (ADR-0009).
- `--yes` on destructive CLI commands is a UX guard, not a security control: it
  is enforced client-side only, so a direct HTTP `DELETE` bypasses it.
- Host hardening remains deployment-dependent (system user, service manager, firewall).
- Privileged Linux networking actions still require elevated permissions on host.
- The Firecracker auto-download path does not yet verify a checksum for the
  fetched hypervisor binary (tracked; version is pinned).

## Planned periodic validation

- CI security gates: `cargo deny`, `cargo audit`, security regression tests.
- Nightly drills: chaos restart + graceful shutdown scripts.
- Pre-release checklist: no open high/critical dependency findings.
