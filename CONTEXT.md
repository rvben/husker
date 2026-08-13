# Domain glossary

## CLI contract

The finite machine interface exposed by `husker schema`: canonical command
paths, mutation policy, structured-output field names and JSON types, and stable
CLI error kinds. Clap owns command syntax; the exhaustive contract registry
owns semantics Clap cannot express. Structured runtime output is validated
through this interface before it is printed.

## Daemon runtime

The supervised lifecycle that begins after a platform branch has assembled its
`HuskerCore`: startup reconciliation, background workers, metrics and API
serving, worker cancellation, VM draining, and outcome preservation. Platform
adapters retain backend construction, host-network preparation, and
host-resource cleanup. The runtime's closed `LinuxNet` mode owns Linux-only
startup recovery and workers without flattening platform networking policy.
