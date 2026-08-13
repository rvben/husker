# Domain glossary

## CLI contract

The finite machine interface exposed by `husker schema`: canonical command
paths, mutation policy, structured-output field names and JSON types, and stable
CLI error kinds. Clap owns command syntax; the exhaustive contract registry
owns semantics Clap cannot express. Structured runtime output is validated
through this interface before it is printed.
