# ADR-0002: API Authentication Model

- Status: Accepted
- Date: 2026-02-16 (amended 2026-08-17 and 2026-10-26)

## Context

Mutating VM control endpoints are high-impact and unsafe to expose unauthenticated beyond localhost.

## Decision

- Keep loopback-only daemon bind as secure default.
- Add optional bearer token auth:
  - public endpoint: `/v1/health`
  - protected when configured: every other API, metrics, and WebSocket endpoint
- Keep auth simple and operator-friendly for local/self-hosted workflows.
- A loopback bind without a token is accepted. Loopback is a host boundary,
  not a user boundary: every local account that can open a TCP connection to
  the port has full control of the daemon, and a TCP listener cannot learn the
  peer's user id to tell accounts apart. The daemon does not try to; on a host
  with more than one interactive or service account, configure `api_token`
  even for a loopback bind.
- A configured token must have content. A blank `api_token` or
  `metrics_token` (from the config file, the environment, or `--api-token`)
  is a start-up error, never "no authentication".
- Define one daemon as one trust domain. The shared token is intentionally not a
  user identity and Husker does not provide tenant ownership or RBAC.
- Keep TLS, client-certificate verification, and service identities at a reverse
  proxy or private service-mesh boundary. The proxy forwards to a loopback-bound
  Husker daemon and supplies the daemon's bearer token.
- Do not add in-process mTLS or multiple service-account tokens before Husker has
  an authorization model capable of assigning meaning to those identities.

## Consequences

- Reduced accidental remote exposure risk.
- Remote deployments need two controls: TLS (or an encrypted private tunnel) for
  transport confidentiality and the bearer token for daemon authentication.
- Operators needing distinct identities or certificate rotation use their
  existing proxy/service mesh and its policy/audit facilities.
- Mutually distrusting callers require separate daemon instances; presenting
  different client certificates to one daemon does not create isolation.
- An eventual multi-tenant authorization design may supersede this decision and
  introduce scoped credentials without changing route semantics.
