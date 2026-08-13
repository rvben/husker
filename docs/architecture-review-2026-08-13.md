# CLI architecture review

Date: 2026-08-13
Baseline: `f1b39e7`

Husker has clear crate-level seams and strong backend ADRs. The remaining CLI
friction is concentrated inside the `husker` binary, where transport, command
policy, rendering, and process behavior still meet in a few wide modules.

## Ranked improvements

### 1. Deepen the daemon adapter — Strong

Status: implemented in this review.

The current HTTP helpers are shallow. Command branches construct URLs, apply
authentication, send requests, check status, parse daemon errors, and decode
raw JSON independently. The same transport tuple leaks into the Job and guest
file modules.

Deepen one daemon adapter that owns endpoint construction, authentication,
connection diagnostics, status-to-error mapping, response decoding, and the
underlying HTTP client. This gives transport policy locality and makes the
adapter interface the transport test surface. It also centralizes the bearer
token behavior required by ADR-0002.

Primary files:

- `crates/husker/src/main.rs`
- `crates/husker/src/job.rs`
- `crates/husker/src/guest_file.rs`

### 2. Complete the Job lifecycle module — Strong

Status: implemented after the daemon adapter.

The Job module owns create, readiness, sync, exec, and retrieval, but its seam
leaks a wide request containing the raw HTTP client, URL, token, and output
policy. Validation, cleanup, interruption, rendering, and exit selection remain
in `main.rs`.

Deepen the module around the complete Job lifecycle and return one typed
outcome to the outer process adapter. Preserve ADR-0005 by continuing to clean
up through daemon VM destruction rather than introducing guest shutdown policy.

Primary files:

- `crates/husker/src/job.rs`
- `crates/husker/src/main.rs`

### 3. Deepen VM creation planning — Strong

Status: implemented after the Job lifecycle.

VM profile precedence and request planning are valuable implementation, but
the current interface mixes filesystem resolution, diagnostics, process exit,
and untyped JSON. Run and Job also reconstruct the same argument shape.

Deepen a VM creation planning module that accepts one creation intent and
returns a typed request plus structured diagnostics. Keep platform capability
truth behind the daemon seam as required by ADR-0001.

Primary files:

- `crates/husker/src/main.rs`
- `crates/husker/src/config.rs`
- `crates/husker-core/src/lib.rs`

### 4. Consolidate daemon target resolution — Worth exploring

Status: implemented after VM creation planning.

Context persistence, SSH tunnel lifetime, effective URL resolution, locality,
capability probing, and connection diagnostics are spread across distant
regions of `main.rs`.

Deepen one target module with direct HTTP and SSH adapters. It should own the
resolved endpoint and tunnel lifetime, then construct the daemon adapter.

Primary file:

- `crates/husker/src/main.rs`

### 5. Eliminate parallel CLI schema policy — Worth exploring

Status: implemented after daemon target resolution.

Clap definitions, hand-maintained schema annotations, emitted JSON, and output
documentation form parallel sources of truth. The schema currently declares
every output field as a string even when the emitted value is numeric or
boolean, while `docs/api/cli-output-json.md` shows obsolete output shapes.

Give command metadata locality with the command definitions, then derive the
clispec and semantic contract tests from that metadata.

Primary files:

- `crates/husker/src/cli.rs`
- `crates/husker/src/schema.rs`
- `crates/husker/tests/schema.rs`
- `docs/api/cli-output-json.md`

### 6. Deepen daemon runtime assembly — Speculative

Core configuration and runtime startup repeat across platform branches. A
shared runtime module could own reconcile, background loops, metrics, serving,
and draining while platform adapters retain backend assembly.

This must not erase the explicit networking and shutdown differences recorded
by ADR-0001 and ADR-0005.

Primary file:

- `crates/husker/src/daemon.rs`

## Recommended order

The first five recommendations are complete: daemon adapter, complete Job
lifecycle, VM creation planning, daemon target resolution, and CLI contract
policy. The strongest remaining candidate is daemon runtime assembly, although
it remains speculative and should be pressure-tested against the platform ADRs
before implementation.

## Implementation note

The new `DaemonClient` now owns the base URL, bearer token, reusable HTTP
client, connection diagnostics, request sending, and stable daemon-error
decoding. CLI commands supply relative operations, and Job plus guest-file
transfer receive the adapter instead of a raw client/URL/token tuple. Streaming
and WebSocket code retains direct response/transport control where that is part
of the command's behavior.

The Job module now owns source validation, VM acquisition, command execution,
Ctrl-C handling, result rendering, exit precedence, and VM cleanup. It exposes
only a typed `JobTermination` to the process adapter. Cleanup is acquisition
aware, so a create conflict cannot destroy a pre-existing VM; cleanup failures
are surfaced, an already-absent VM counts as clean, and a command's non-zero
exit code remains primary when cleanup also fails.

The new VM creation module accepts one `VmCreationIntent` from either `run` or
`job`, resolves daemon/local profiles and their path semantics, validates every
pool conflict, reads userdata and SSH keys, and returns structured diagnostics
plus the canonical `husker_core::CreateVmRequest`. A typed preparation state
ensures local prerequisites cannot be skipped. Firecracker preparation and
missing-default diagnostics run only for a genuinely local target, so a remote
daemon reached through an SSH loopback tunnel is never mistaken for the local
host. The planner owns pool checkout as the other acquisition variant, and the
Job lifecycle consumes the same prepared plan as `run`.

The new daemon target module owns context persistence, precedence resolution,
URL validation, direct-versus-SSH transport selection, parsed-host locality,
SSH process lifetime, and construction of the authenticated `DaemonClient`.
Command dispatch now carries one connected `DaemonTarget`, so helpers cannot
quietly reconstruct clients with different authentication or timeout policy.
Local-only commands return before daemon resolution, host-local operations
reject remote targets before opening a tunnel, and an SSH tunnel's loopback
endpoint can no longer make the remote daemon appear local.

The new CLI contract module provides the test surface for mutation policy,
structured-output fields and types, and the finite stable error vocabulary. An
exhaustive registry beside the Clap definitions gives the policy locality: a
missing, duplicate, or stale command contract now fails the deletion test.
Clispec argument types and defaults are derived from Clap's actual parsers, and
JSON payloads are validated through the registry before rendering. List fields
follow clispec v0.2 item semantics, documentation examples are executable
contract samples, unsupported structured modes fail cleanly, and unknown
daemon-specific error kinds normalize at the CLI seam. ADR-0007 records the
compatibility policy.
