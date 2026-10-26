# Security Hardening Guide

## 1. API exposure

- Keep daemon on loopback whenever possible:
  - `husker daemon --listen 127.0.0.1:7777`
- Loopback is reachable by every local account on the host, and the daemon
  cannot tell them apart over TCP. On a host with more than one interactive or
  service account, set `api_token` even for a loopback bind.
- If remote bind is required:
  - use `--allow-remote` explicitly
  - set `api_token` in config
  - restrict source networks via host firewall/reverse proxy

## 2. Authentication

- Configure a high-entropy bearer token:
  - `api_token = "<long-random-secret>"`
- A blank token is refused: the daemon exits at start when `api_token` (from
  the config file, `HUSKER_API_TOKEN`, or `--api-token`) is set but empty or
  whitespace-only, so a failed secret substitution cannot pass for
  authentication. The same applies to `metrics_token`.
- Rotate token on incident response or operator turnover.
- Treat one daemon and its token as one trust domain. A token holder has full
  control of every VM, volume, and secret on that daemon.
- Use separate daemon instances for mutually distrusting callers.

## 3. Least privilege policy

- Constrain guest file access:
  - `allowed_read_paths = ["/tmp", "/var/log"]`
  - `allowed_write_paths = ["/tmp"]`
- Constrain command execution:
  - `exec_allowlist` and `exec_denylist`
  - `exec_env_allowlist`
  - `exec_timeout_secs`

## 4. Host filesystem paths

- Requests name host files: VM images and kernels, import sources, export
  destinations and `--mount` hosts. The daemon opens them as its own user, and
  that user's permissions are the boundary (ADR-0009). Run the daemon as a
  dedicated account that owns the data directory and nothing it should not
  read, clone or write.
- Keep images and kernels inside the data directory (`husker images pull`,
  `husker images import`) so the paths a caller can name are the ones you
  intend.
- Opt mounts in narrowly with `allowed_mount_host_paths`; the empty default
  denies every mount. The match is a lexical prefix check after normalisation
  and does not resolve symlinks, so list the real directories and keep
  symlinks out of them. Do not list `/home` or `/`.
- Import, export and mount paths must be absolute, contain no `..` and not
  end in a symlink, and an export never overwrites an existing file. These are
  mistake guards, not a sandbox.

## 5. Abuse controls

- Keep endpoint rate limits enabled:
  - `api_sensitive_rate_limit_per_minute = 120` (or lower for shared deployments)
- Tune body/file limits to operational needs:
  - `api_max_request_bytes`
  - `api_max_file_read_bytes`
  - `api_max_file_write_bytes`

## 6. Host posture

- Run daemon as a dedicated non-login service account where possible.
- Grant only required capabilities for networking (`CAP_NET_ADMIN`) on Linux deployments that need bridge/NAT.
- Restrict filesystem write access to data/runtime directories only.
- On macOS the daemon runs as the logged-in user and can reach every file that
  user can; the loopback bind and the bearer token are the controls there.

## 7. Network topology recommendations

- Preferred: local daemon behind SSH tunnel or private service mesh.
- Remote control plane: terminate TLS at a reverse proxy, optionally require
  client certificates or workload identities there, and forward only over
  loopback to Husker. Configure the proxy to inject Husker's bearer token after
  it authenticates the caller rather than exposing that token to callers.
- Bind the upstream daemon to `127.0.0.1`; the public listener belongs to the
  TLS proxy. Preserve WebSocket upgrades for `exec/stream` and `shell`.
- Restrict direct access to the daemon port with the host firewall so callers
  cannot bypass proxy identity policy.
- Avoid exposing daemon directly on public interfaces.
- Give untrusted jobs `network: "none"`, or use `network: "filtered"` with the
  smallest practical destination/port set. Plain `nat` is unrestricted egress.
  See [Per-VM egress policies](egress-policies.md).

## 8. Logging and monitoring

- Collect API logs with request IDs (`x-request-id`).
- Alert on:
  - repeated `rate_limited` responses
  - repeated auth failures
  - repeated policy denials

## 9. Dependency and supply chain controls

- Enforce CI gates:
  - `make deny`
  - `make audit`
- Keep dependency update workflow active.
