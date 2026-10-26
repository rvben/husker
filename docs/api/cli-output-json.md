# CLI JSON Output Contract

Request structured output with:

```bash
husker --output json <command> ...
```

The canonical, versioned contract is emitted by `husker schema`. Its command
tree comes from the same Clap definitions as the CLI, while mutation policy,
output field names, and JSON types come from the exhaustive command contract
registry. CI verifies that every command leaf has exactly one contract.

## Conventions

- Most command results are objects with `status: "ok"` and an `action`.
- `exec` and `job` run a guest command and pass its exit code through: their
  `status` is the guest command's result (`ok` for exit code 0, `error`
  otherwise) and the process exits with that code. No error envelope is
  written, since the tool itself did not fail; the absence of an envelope on
  stderr tells a guest exit code apart from a tool error with the same code.
  `husker schema` declares the pass-through under those commands'
  `extensions`.
- Resource payloads remain nested (`vm`, `image`, `service`, and so on) so new
  resource fields can be added without changing the command envelope.
- In clispec v0.2, `output_fields` for a list command describe one item in its
  result array. They do not describe the pagination or command envelope.
- Optional values use union types such as `string|null` and `boolean|null`.
- JSON is the only content written to stdout. Progress and diagnostics go to
  stderr.
- Text output is human-oriented and is not a machine contract.

Some local, interactive, or streaming commands do not define structured
output: `daemon`, `guest-agent`, `shell`, `setup storage`, `completions`,
`preview`, `logs --follow`, and `events --follow`.
Their schema entries have no `output_fields`. An explicit `--output json` on
one of them is refused before any request reaches the daemon, with the
`invalid_usage` kind and a hint naming the supported form (text output, or the
command's non-streaming JSON variant), rather than emitting a partial or mixed
stream. `config check` is structured: it emits one report with a stable overall
status and an array of named checks.

## Examples

### List VMs

`list` is paginated and intentionally distinguishes an unreachable daemon from
a genuinely empty fleet:

```json
{
  "items": [],
  "total": 0,
  "limit": 100,
  "offset": 0,
  "daemon_reachable": true
}
```

### VM details

```json
{
  "status": "ok",
  "action": "info",
  "vm": {
    "name": "myvm",
    "state": "running"
  }
}
```

### Exec

```json
{
  "status": "ok",
  "action": "exec",
  "vm": "myvm",
  "result": {
    "exit_code": 0,
    "stdout": "hello\n",
    "stderr": ""
  }
}
```

A command that exits nonzero has the same shape with `status: "error"` and
its code in `result.exit_code`, and `husker` exits with that code.

## Errors

Structured errors are a single JSON line on stderr:

```json
{
  "error": {
    "kind": "not_found",
    "message": "VM 'ghost' not found",
    "hint": "check the VM name"
  }
}
```

`hint` is optional. `husker schema` publishes the finite set of stable CLI
error kinds and their exit codes. More specific error kinds received from a
newer daemon are normalized to the CLI's stable categories, so the advertised
set remains exhaustive.

## Stability policy

- Existing structured-output keys and error kinds are additive-only within a
  major release.
- Consumers must ignore unknown fields.
- A field's JSON type is part of the contract.
- Changes to command syntax, mutation policy, output shape, or errors must
  update the typed registry and its semantic tests in the same change.
