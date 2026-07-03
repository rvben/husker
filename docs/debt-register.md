# Technical Debt Register

> Reviewed 2026-07-03. Overdue due dates were refreshed to review-by placeholders
> (not roadmap commitments); see the status notes below the table. Items marked
> "needs owner status" await a maintainer call.

| ID | Area | Severity | Owner | Due date | Description | Mitigation plan |
|---|---|---|---|---|---|---|
| DEBT-001 | Auth | Medium | Platform | 2026-09-30 | Bearer-token-only remote auth model | Evaluate mTLS/service-account integration |
| DEBT-002 | CLI | Low | CLI | 2026-09-30 | `config check` lacks JSON output mode | Add structured check report schema |
| DEBT-003 | Testing | Medium | QA | 2026-09-30 | Ignored e2e suites need privileged runner availability | Provision dedicated nightly runners and enable gate vars |
| DEBT-004 | Performance | Medium | Runtime | 2026-09-30 | Perf baseline covers read-path APIs only | Extend to lifecycle/exec/shell/log streaming workloads |
| DEBT-005 | Protocol | Low | Agent | 2026-09-30 | No libFuzzer lane yet for agent framing | Add `cargo-fuzz` target in nightly pipeline |
| DEBT-006 | Images | Low | VMM | 2026-07-31 | Default image's `hvc0` getty (for Apple VZ virtio-console) spams `can't open /dev/hvc0` under serial-console backends (QEMU and Firecracker) | Gate the `hvc0` getty to the VZ image variant, or have backends expose a matching virtio-console |
| DEBT-007 | Runtime | Low | VMM | 2026-07-31 | A daemon SIGKILL orphans the live VMM process (QEMU/Firecracker); `mark_stale_vms_stopped` updates DB state but does not reap the process | Add pidfile-based orphan reaping on daemon startup (QEMU already writes a pidfile) |

## Status review (2026-07-03)

- **DEBT-001** - Remote auth was hardened (deny-by-default protected routes,
  non-loopback bind now requires a token, constant-time token compare,
  no-multi-tenancy documented in the threat model). The mTLS/service-account
  model itself is untouched. *Needs owner status:* is mTLS on the roadmap, or is
  the documented single-shared-token model accepted?
- **DEBT-002** - *Needs owner status:* could not confirm a `config check` JSON
  mode in the current CLI; unclear whether this item is still relevant.
- **DEBT-003** - Mitigation partly done: the ignored e2e are now wired
  (`idle-policy-e2e.yml` nightly; `qemu-e2e.yml`/`vz-cloud-e2e.yml` dispatch) with
  honest skip warnings. **Outstanding (owner):** provisioning the privileged
  nightly runner(s) and setting the gate repo vars so they actually run green.
- **DEBT-004** - Still open; ties to the missing boot/checkout latency lane.
  *Needs owner status* on priority (needs a KVM/Firecracker runner to build).
- **DEBT-005** - Partially mitigated: the mutation gate now runs real
  `cargo-mutants` on the `husker-agent-proto` framing + base64 (0 missed),
  covering a related class of framing defects. A `cargo-fuzz` lane for
  adversarial framing inputs is still absent but lower urgency.
- **DEBT-006** - Open, not yet due. No change.
- **DEBT-007** - Largely addressed: `reap_vmm_if_orphaned` reaps orphaned VMM
  processes from a prior daemon on startup (logs "reaped orphaned VMM process
  from a prior daemon"). Owner to confirm this covers the SIGKILL case and close.
