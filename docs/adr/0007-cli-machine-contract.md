# ADR-0007: CLI Machine Contract

- Status: Accepted
- Date: 2026-08-13

## Context

Husker supports machine consumers through `--output json` and `husker schema`.
Command syntax came from Clap, but mutation policy, output annotations, runtime
JSON objects, and documentation evolved independently. The schema therefore
remained structurally valid while reporting incorrect types and obsolete
shapes. It also advertised a finite error vocabulary while forwarding arbitrary
daemon error kinds.

## Decision

- Clap remains the source of truth for command syntax, argument types, choices,
  and defaults.
- An exhaustive typed command-contract registry beside the Clap definitions
  owns mutation policy and structured-output field names and JSON types.
- Every Clap leaf has exactly one registry entry. Missing, duplicate, and stale
  entries fail semantic contract validation; there is no default mutation or
  output policy.
- Structured runtime success payloads are validated against the registry before
  they are written to stdout. In clispec v0.2, list-command `output_fields`
  describe one list item rather than its envelope.
- The CLI publishes a finite set of stable error kinds. Daemon-specific kinds
  that are not in that vocabulary are normalized by exit-code category at the
  CLI boundary.
- JSON output keys and types are additive-only within a major release. Commands
  without a structured result reject `--output json`.
- `husker schema` is the canonical reference. Documentation examples are
  illustrative and are validated against the same runtime interface in tests.

## Consequences

- Adding or renaming a command requires an explicit semantic decision.
- Output drift is detected where JSON is rendered instead of relying only on a
  structurally valid clispec document.
- Automation can safely use `mutating: false`, including for approval policy.
- New daemon error detail remains available through the HTTP API, while the CLI
  stays compatible with its finite advertised vocabulary.
