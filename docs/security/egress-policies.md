# Per-VM egress policies

Linux API clients can give one VM a narrow outbound network boundary. A policy
is opt-in and default-deny: traffic not needed for the configured gateway and
DNS resolvers, or not named by an allow rule, is dropped.

```json
{
  "name": "werkt-run-01",
  "rootfs_path": "python:3.13-alpine",
  "network": "filtered",
  "egress": [
    { "host": "api.github.com", "port": 443, "protocol": "tcp" },
    { "host": "ntfy.example.net", "port": 443, "protocol": "tcp" }
  ]
}
```

`filtered` and a non-empty `egress` list must appear together. Do not send the
rules with `network: nat`: Husker rejects that combination. The separate wire
value also makes the capability fail closed against older daemons, which do not
recognize `filtered`.

## Enforcement model

- Hostnames resolve before VM resources are allocated. Only their current IPv4
  answers are installed; DNS changes do not widen a running VM's access.
- Rules match the kernel-provided ingress TAP, not a guest-controlled source IP.
- Each allow entry is an exact IPv4 destination, TCP or UDP protocol, and port.
- DNS is admitted only to the daemon's configured IPv4 resolvers on port 53.
- ARP is admitted only for the configured gateway. Other layer-2 traffic and
  IPv6 are denied.
- Input and forwarding rules are replaced atomically in nftables before guest
  boot. The concrete policy is persisted and reconciled at daemon startup.
- Forked VMs inherit the source VM's pinned policy.

The request accepts at most 32 entries and at most 128 resolved concrete rules.
Wildcards, URLs, CIDRs, port zero, IPv6-only destinations, and non-unicast IPv4
addresses are rejected. Use `network: "none"` when a job needs no network.

## Limits

This is destination filtering, not application-layer authorization. An allowed
server can still proxy traffic or change behavior, and TLS identity remains the
guest application's responsibility. DNS answers are intentionally pinned for
the VM lifetime, so long-running guests may need recreation after an upstream
address change. The feature requires Linux host networking; Apple VZ cannot
enforce it and rejects the request.
