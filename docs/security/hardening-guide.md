# Security Hardening Guide

## 1. API exposure

- Keep daemon on loopback whenever possible:
  - `husker daemon --listen 127.0.0.1:7777`
- If remote bind is required:
  - use `--allow-remote` explicitly
  - set `api_token` in config
  - restrict source networks via host firewall/reverse proxy

## 2. Authentication

- Configure a high-entropy bearer token:
  - `api_token = "<long-random-secret>"`
- Rotate token on incident response or operator turnover.

## 3. Least privilege policy

- Constrain guest file access:
  - `allowed_read_paths = ["/tmp", "/var/log"]`
  - `allowed_write_paths = ["/tmp"]`
- Constrain command execution:
  - `exec_allowlist` and `exec_denylist`
  - `exec_env_allowlist`
  - `exec_timeout_secs`

## 4. Abuse controls

- Keep endpoint rate limits enabled:
  - `api_sensitive_rate_limit_per_minute = 120` (or lower for shared deployments)
- Tune body/file limits to operational needs:
  - `api_max_request_bytes`
  - `api_max_file_read_bytes`
  - `api_max_file_write_bytes`

## 5. Linux host posture

- Run daemon as a dedicated non-login service account where possible.
- Grant only required capabilities for networking (`CAP_NET_ADMIN`) on Linux deployments that need bridge/NAT.
- Restrict filesystem write access to data/runtime directories only.

## 6. Network topology recommendations

- Preferred: local daemon behind SSH tunnel or private service mesh.
- Remote control plane: terminate TLS at reverse proxy, enforce authn/authz before forwarding to husker.
- Avoid exposing daemon directly on public interfaces.

## 7. Logging and monitoring

- Collect API logs with request IDs (`x-request-id`).
- Alert on:
  - repeated `rate_limited` responses
  - repeated auth failures
  - repeated policy denials

## 8. Dependency and supply chain controls

- Enforce CI gates:
  - `make deny`
  - `make audit`
- Keep dependency update workflow active.
