# CLI JSON Output Contract

Global flag:

```bash
husker --output json <command> ...
```

## Common conventions

- Success payloads include:
  - `status: "ok"`
  - `action: "<command-action>"`
- Error payloads include:
  - `status: "error"`
  - `error: "<message>"`

## Examples

### List VMs

```json
{
  "status": "ok",
  "action": "list",
  "vms": []
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

### Error

```json
{
  "status": "error",
  "error": "VM 'ghost' not found"
}
```

## Stability policy

- Existing keys are additive-only within a major release.
- Consumers should ignore unknown fields.
- For streaming logs (`logs --follow`), JSON output is intentionally unsupported.
