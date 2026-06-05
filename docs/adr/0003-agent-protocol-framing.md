# ADR-0003: Agent Protocol Framing

- Status: Accepted
- Date: 2026-02-16

## Context

Host/guest communication requires a portable framing format over vsock and WebSocket relay paths.

## Decision

- Use length-prefixed JSON messages.
- Use base64 for binary payload fields.
- Keep protocol crate (`husker-agent-proto`) shared by daemon/client/agent.
- Validate with roundtrip, integration, and property tests.

## Consequences

- Debuggable protocol during incidents.
- Slight encoding overhead vs binary-only formats.
- Enables stable schema validation and fuzz/property expansion.
