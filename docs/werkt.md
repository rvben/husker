# Werkt integration

[Werkt](https://github.com/rvben/werkt) uses Husker as its isolated execution plane. Werkt remains responsible for triggers, durable events, scheduling, retries, concurrency, revisions, and run history. Husker is responsible for creating a guest, enforcing its resources and network topology, executing commands through the guest agent, and destroying the guest.

## Ephemeral VM contract

`POST /v1/vms` accepts two optional orchestration fields in addition to the existing flat VM request:

```json
{
  "name": "werkt-0123456789abcdef",
  "rootfs_path": "python:3.13-alpine",
  "vcpu_count": 1,
  "mem_size_mib": 256,
  "network": "none",
  "expires_after_secs": 450,
  "owner": "werkt/run_01..."
}
```

`expires_after_secs` must be greater than zero. Husker computes the absolute deadline on receipt and persists it atomically with the VM generation. `owner` is optional correlation metadata and requires an expiration; it is not an authorization primitive.

VM list, get, and create responses expose `expires_at` and `owner` when configured. The daemon checks deadlines every five seconds and also checks immediately after startup. Expiration is a hard lifetime: open sessions, network traffic, paused state, and idle-policy settings do not extend it. Failed cleanup remains durable and is retried on the next tick.

## Build and runtime flow

For a compiled automation, Werkt first cold-boots a builder VM with `owner: werkt/build/<automation-id>`, uploads its source, invokes the manifest's build command, and downloads the resulting workspace through ranged file reads. It safely promotes that workspace into the immutable revision and destroys the builder.

For each run attempt, Werkt cold-boots a separate VM, waits for the guest agent, uploads its immutable artifact and event through the file API, invokes the automation through the exec API, reads the JSON result, and destroys the VM. Cleanup uses a context independent from the automation timeout. Durable expirations cover both VM types when a worker crashes or a network partition prevents explicit cleanup.

Werkt defaults builders to `network: nat` for dependency resolution and runtime VMs to `network: none`; these policies are configured independently. Current Firecracker pool forks are NAT-only, so Werkt intentionally does not use pools yet. An isolated pool path must preserve no-network semantics and attach expiration metadata atomically at checkout before it is suitable as the default fast path.

## Trust boundary

Use bearer-token authentication and keep Werkt and Husker in the same trust domain. Husker currently treats authenticated callers as operators of the whole daemon; `owner` does not restrict who can inspect, execute in, or destroy a VM. Separate daemon instances are required for separate trust domains today.
