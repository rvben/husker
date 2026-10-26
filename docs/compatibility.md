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
  - error JSON always uses `{ "error": { "kind", "message", "hint"? } }`;
    `message` says what failed and `hint` is the only field that carries a
    remedy (see `docs/api/cli-output-json.md`)
  - error kinds are the finite set `husker schema` lists under `errors`; a
    kind a newer daemon sends is normalized to that set by exit code
- A destructive command that does not pass its confirmation gate changes
  nothing and exits 6: `confirmation_required` when stdin is not a TTY and
  `--yes` is absent, `confirmation_declined` when the prompt was answered no.
- An operation that does not finish in time exits 1 with the `timeout` kind:
  `wait` and `job` past their ready deadline, a preview handshake that never
  completes, and a command the daemon ended at its run timeout (the API's
  `exec_timeout`). It is not marked retryable, since a timed-out command may
  have completed in the guest.
- `exec`, `job` and `shell` exit with the guest command's exit code, and
  `exec` and `job` report `status: "error"` in their JSON result when it is
  nonzero. A guest exit code is the command's result, not a tool error: no
  envelope is written, and the code may coincide with any of the tool's exit
  codes. `husker schema` declares the pass-through under those commands'
  `extensions`.

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
- The session routes (`/v1/vms/{name}/sessions...`) and the preview tunnel
  (`/v1/vms/{name}/tunnel/{port}`) answer a refusal from the guest agent by
  its class, which the agent reports as a code beside the message (a guest
  agent from 0.4.51 or 0.4.52 reports only the message; the daemon
  classifies those by their unchanged wording):
  - `invalid_session_id` (400): the id is not one of the UUIDs a start returned
  - `session_not_found` (404)
  - `session_conflict` (409): the retention limit is reached, the session is
    still running, or a generated id collided; the `hint` says which
  - `session_capacity_exhausted` (429): too many running sessions
  - `guest_capability_missing` (501): the guest agent predates sessions
  - `preview_unreachable` (502): nothing on the guest accepted the tunnel
    connection
  - `session_failed` (502): a guest-side failure without a class, with the
    agent's message
  - `agent_not_ready` (503): the guest did not answer within the transport
    deadline, the same status and kind as every other agent deadline in the
    API. A session start may already have been accepted when this is
    returned, so list the sessions before retrying one. Daemons before 0.4.53
    answered this case with 504 `session_timeout`, and a slow tunnel connect
    with 504 `preview_connect_timeout`; both are now 503 `agent_not_ready`.

## Deprecation workflow

1. Mark deprecated field/endpoint in docs and OpenAPI description.
2. Emit migration note in `CHANGELOG.md`.
3. Keep behavior for at least one minor release unless security-critical.
4. Remove only in next major release.
