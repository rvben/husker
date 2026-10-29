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
  - serial log truncation notices: each VM's serial log is capped at 8 MiB,
    and on overflow the oldest output is dropped behind a
    `[husker: earlier serial output discarded: N bytes]` marker counting every
    byte dropped so far. A follow session continues across these compactions
    and prints `[... N serial bytes discarded before they were shown ...]`
    only when it fell behind, or `[... serial log restarted ...]` when the VM
    booted again with a fresh log
- Actions:
  - reconnect follow session
  - inspect host disk pressure

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

## 11. Fork source reconciliation pending

- Symptom: stop, resume, delete, fork, snapshot or image commit of a VM fails
  with `fork source reconciliation pending`, and the daemon logs `fork source
  reconciliation pending` at startup.
- Cause: a fork of this VM was interrupted while the source's
  `<data_dir>/vms/<name>/rootfs.ext4` was a symlink to the fork's clone (a fork
  restores its snapshot through the source's disk path). The real disk is in
  `rootfs.ext4.fork-src-bak` beside it. Until a fork process confirms its
  snapshot loaded, it can still open the symlink, so the daemon cannot tell when
  the original disk is safe to put back and blocks the VM instead.
- Checks: `lsof` or `fuser` showing nothing open is not enough. A fork that has
  not loaded its snapshot yet holds no descriptor, and will open the path later.
- Actions (offline, as root):
  1. Stop the daemon and anything that can start VMs on this host:
     `systemctl stop husker`.
  2. Make sure none of this daemon's Firecracker processes remain. List every
     Firecracker on the host with `pgrep -af -- '--[a]pi-sock'` (the brackets
     keep the shell running `pgrep`, under `sudo sh -c` or `ssh`, out of the
     list). Each one this daemon starts, forks included, has its API socket in
     `<state_dir>/run/`, where `<state_dir>` is the directory holding the
     daemon's `husker.lock` (`HUSKER_STATE_DIR` in the unit's environment
     overrides `state_dir` in the config, which defaults to `data_dir`).
     - A process whose socket is in `<state_dir>/run/` belongs to a daemon that
       is gone: confirm `readlink /proc/<pid>/exe` is the Firecracker binary,
       then `kill <pid>`, which ends that guest without a clean shutdown.
     - A process whose socket is elsewhere must belong to a service you can
       name, such as another daemon with its own state directory; leave it.

     Re-run `pgrep` until every remaining process is of the second kind. If one
     will not exit or cannot be accounted for, reboot with the service disabled
     (`systemctl disable husker`) instead.
  3. In `<data_dir>/vms/<name>/`, confirm `rootfs.ext4.fork-src-bak` is a
     regular file (`stat`), and that `rootfs.ext4` is a symlink or absent. Any
     other combination needs manual investigation; do not continue.
  4. Put the original back atomically:
     `mv -T rootfs.ext4.fork-src-bak rootfs.ext4`.
  5. Leave the clone the symlink pointed to; it belongs to the fork VM, and
     deleting that VM removes it. It may already be gone: a fork that died
     before its record was saved leaves a directory with no VM record, which
     the daemon's startup sweep deletes. The source no longer needs it once
     step 4 is done.
  6. Start the service (and re-enable it if step 2 disabled it).
- Never delete `rootfs.ext4.fork-src-bak` to clear the error. That lifts the
  block while `rootfs.ext4` still points at the fork's disk, and the source VM
  then boots and writes the fork's clone.
