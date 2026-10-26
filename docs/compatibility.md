# Compatibility and Deprecation Policy

## API compatibility

- Backward-compatible changes:
  - adding optional response fields
  - adding new endpoints
  - broadening accepted input where behavior is unchanged
- Breaking changes require:
  - major version bump
  - migration note in changelog
  - deprecation window where practical

## CLI compatibility

- Default text output is human-oriented and may improve wording.
- `--output json` is contract-oriented:
  - `husker schema` is the canonical machine-readable command contract
  - command payload keys are additive-only within a major release
  - documented field types are stable within a major release
  - error JSON always uses `{ "error": { "kind", "message", "hint"? } }`

## Error contract

- API error schema uses:
  - `kind`
  - `message`
  - optional `hint`
  - optional `details`
  - backward-compatible alias `error`
- Requests the API refuses before a handler runs use the same schema. Their
  status codes are the HTTP conventions and their kinds are stable:
  - `invalid_json` (400): the body is not JSON
  - `invalid_request_body` (422): the body is JSON of the wrong shape, with
    the field in `message`
  - `payload_too_large` (413): the body exceeds `max_request_bytes`
  - `unsupported_media_type` (415): no `Content-Type: application/json`
  - `invalid_query` (400) and `invalid_path` (400): a query or path
    parameter does not parse, with the raw value in `message`
  - `websocket_upgrade_required` (400 or 426): a WebSocket route opened
    without an upgrade
  - `route_not_found` (404) and `method_not_allowed` (405, with the `Allow`
    header)
- The WebSocket routes (`/v1/vms/{name}/exec/stream`, `/v1/vms/{name}/shell`)
  refuse an unknown VM before the upgrade with the normal 404 `vm_not_found`
  envelope. A failure after the upgrade cannot change the HTTP status, so it
  arrives as one text frame `{ "type": "error", "kind", "message", "hint"?,
  "status" }` and the socket closes: `kind`, `message` and `hint` are the REST
  envelope for the same failure and `status` is the HTTP status the REST
  routes answer with, so one status mapping serves both transports. A first
  frame that is not the text `start` message is reported as
  `invalid_start_message` (400). Frames from daemons older than this contract
  carry only `message`.

## Deprecation workflow

1. Mark deprecated field/endpoint in docs and OpenAPI description.
2. Emit migration note in `CHANGELOG.md`.
3. Keep behavior for at least one minor release unless security-critical.
4. Remove only in next major release.
