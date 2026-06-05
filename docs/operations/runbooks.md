# Operations Runbooks

## 1. Daemon not reachable

- Symptom: CLI returns `cannot connect to daemon`.
- Checks:
  - `husker version` (daemon section absent)
  - process/service status
- Actions:
  - restart daemon
  - verify bind address and firewall
  - inspect daemon logs for startup failures

## 2. Auth failures (`401 unauthorized`)

- Symptom: mutating endpoint calls rejected.
- Checks:
  - configured `api_token`
  - client `Authorization: Bearer ...`
- Actions:
  - rotate token if leak suspected
  - update client config/env

## 3. Rate limiting (`429`)

- Symptom: `rate_limited` responses on exec/files/shell.
- Checks:
  - request volume and client source
  - current `api_sensitive_rate_limit_per_minute`
- Actions:
  - backoff/retry at client
  - adjust limit with capacity validation

## 4. Agent not ready (`503`)

- Symptom: exec/files return `agent_not_ready`.
- Checks:
  - VM state is `running`
  - guest boot completion
- Actions:
  - retry after boot delay
  - inspect guest serial logs (`husker logs <vm>`)

## 5. Port-forward drift after restart

- Symptom: state has forwards but packets do not route.
- Checks:
  - daemon startup logs mention reconciliation count
  - `husker pf <vm> list`
- Actions:
  - restart daemon to trigger reconciliation
  - verify nftables table health on host

## 6. Serial log stream appears stalled

- Symptom: `husker logs -f` stops unexpectedly.
- Checks:
  - VM still running
  - serial log rotation/truncation notices
- Actions:
  - reconnect follow session
  - inspect host disk pressure and rotation cadence

## 7. VM lifecycle command appears stuck

- Symptom: stop/pause/resume does not complete promptly.
- Checks:
  - API request logs with `x-request-id`
  - backend process health
- Actions:
  - run graceful-shutdown drill for environment sanity
  - escalate to forced teardown path if required

## 8. High API error rate

- Symptom: `husker_api_errors_total` spike.
- Checks:
  - `/v1/metrics` counters
  - recent deploy/config changes
- Actions:
  - rollback recent change
  - isolate failing endpoint via request IDs

## 9. Dependency vulnerability finding

- Symptom: CI `audit`/`deny` failure.
- Checks:
  - advisory details
  - reachable code path
- Actions:
  - patch dependency
  - document temporary exception with expiry if unavoidable

## 10. Abrupt daemon crash/restart handling

- Symptom: daemon killed or host restarted unexpectedly.
- Checks:
  - service restarts successfully
  - `/v1/health` returns `ok`
- Actions:
  - run `make chaos-tests`
  - verify persisted VM/state consistency after restart
