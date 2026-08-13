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
- Resource payloads remain nested (`vm`, `image`, `service`, and so on) so new
  resource fields can be added without changing the command envelope.
- In clispec v0.2, `output_fields` for a list command describe one item in its
  result array. They do not describe the pagination or command envelope.
- Optional values use union types such as `string|null` and `boolean|null`.
- JSON is the only content written to stdout. Progress and diagnostics go to
  stderr.
- Text output is human-oriented and is not a machine contract.

Some local, interactive, or streaming commands do not define structured
output: `daemon`, `shell`, `config check`, `setup storage`, `completions`, and
`logs --follow`. Their schema entries have no `output_fields`; unsupported JSON
modes fail rather than emitting a partial or mixed stream.

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
