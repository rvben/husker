# Security Regression Suite

## Scope

- Auth bypass attempts on protected endpoints
- Unsafe default prevention (non-loopback bind guard)
- Abuse controls (sensitive endpoint rate limiting)
- Policy enforcement (guest path allowlists, exec allow/deny/env)

## Automated checks

- API auth and protected-route tests:
  - `cargo test -p husker-api auth_enabled_`
- Rate limiting and policy checks:
  - `cargo test -p husker-api rate_limiter_blocks_when_limit_reached`
  - `cargo test -p husker-api allowlist_path_enforcement`
  - `cargo test -p husker-api exec_policy_allow_deny_and_env`
- CLI unsafe default guard:
  - `cargo test -p husker daemon_bind_non_loopback_requires_allow_remote`

## CI enforcement

- `Security Audit` job (`cargo audit`)
- `Dependency Policy` job (`cargo deny`)
- Contract and failure-injection lanes (defense-in-depth against regressions)
