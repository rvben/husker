# ADR-0009: Host Path Trust Model

- Status: Accepted
- Date: 2026-10-26

## Context

Several API requests name files on the daemon host: the rootfs, kernel,
initrd, cloud image and macOS image of a new VM, the source of an image
import, the destination of an image export, and the host side of a `--mount`
share. The daemon opens every one of them with its own credentials. ADR-0002
defines one daemon and its bearer token as one trust domain, with no
per-caller identity, so the question is not which caller may name which path
but which host files the daemon as a whole may touch.

## Decision

- The daemon's own operating-system identity is the boundary for host file
  access. Which files a daemon can read, clone or write is decided by the user
  it runs as, that user's filesystem permissions and any service-manager
  sandboxing, not by a per-request allowlist inside the daemon.
- Image, kernel, initrd and cloud-image paths are accepted from authenticated
  callers as given. A kernel is checked for a recognised image format and a
  cloud image for a self-contained qcow2 header, so a wrong file fails early;
  a rootfs is only required to exist. Nothing restricts where they live.
- Import sources, export destinations and mount hosts pass one guard against
  mistakes: the path must be absolute, must not contain `..`, and its final
  component must not be a symlink. An export never overwrites an existing
  file.
- Host mounts additionally require the operator's opt-in through
  `allowed_mount_host_paths`. The list is empty by default, which denies every
  mount. A requested path matches when, after lexical normalisation, it equals
  an entry or lies beneath one. Symlinks are not resolved: the allowlist
  scopes what an operator may ask for, it does not confine a hostile caller.
- No path canonicalisation, realpath confinement or allowlist for image paths
  is added. Any such check would duplicate the kernel's permission model with
  a weaker copy and would still be bypassable by whoever controls the files
  the daemon is allowed to read.

## Consequences

- A token holder can make the daemon read any file its user can read, by
  booting a VM from it or importing it, and can write an image to any
  location its user can create. Within the trust domain of ADR-0002 that is
  the operator acting on their own daemon.
- Deployments therefore run the daemon as a dedicated user that owns only the
  data directory and the directories it is meant to share, and grant network
  capabilities rather than root where the host allows it. The hardening guide
  carries the concrete posture.
- On macOS the daemon runs as the logged-in user and can reach everything that
  user can. The loopback bind and the bearer token are the controls there.
- Operators who need per-caller path restrictions place them in the proxy or
  orchestrator that holds the token, as ADR-0002 already requires for
  per-caller identity.
