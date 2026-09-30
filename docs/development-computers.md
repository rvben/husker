# Development computers

Prepare a development image once, create a VM from it, start detached commands,
reconnect to their logs, and preview an application through the selected daemon.
The native CLI works with HTTP, HTTPS, and SSH contexts. A Mac can drive a Linux
Firecracker host without exposing its daemon port.

This workflow requires the updated daemon **and guest agent protocol v5**.
Rebuild prepared images after upgrading the guest agent; updating the host binary
alone does not update an existing guest disk. Earlier guest agents receive an
explicit capability error for sessions and tunnels.

## Prepare and create

On a Linux host, build the daemon with the embedded guest agent using
`make build-with-agent` (or the release equivalent), and install the current
container-capable kernel. Configure the daemon's default kernel before preparing
an image. OCI import and the Ubuntu preparation recipe require Linux; suspend and
fork require Firecracker. The session and tunnel protocols work across backends.

```sh
# Optional: select an existing Linux host from a Mac client.
husker context add dev ssh://user@linux-host
husker context use dev

# Downloads Ubuntu and installs tools inside a disposable builder VM.
husker dev prepare --image dev-v1
husker dev new project --image dev-v1
husker dev check project
```

The image includes Git, Node 22, Python, Rust, Docker/Compose, Codex, and Claude
Code. `dev new` starts Docker and checks the installed tools before returning.
`/workspace` belongs to the `developer` user, which has sudo and Docker access
inside the VM. The root disk defaults to 20 GiB and memory to 4 GiB.

Use `--base ubuntu@sha256:...`, `--rust`, `--codex`, and `--claude` to pin the base
and agent versions. Defaults follow the Ubuntu tag, Node 22 release line, and
latest npm agent packages. Apt packages follow the configured Ubuntu repositories.
Resolved tool/package versions are recorded at `/etc/husker/dev-manifest.txt`;
this is a record of the build, not a hermetic-build guarantee.

Preparation does not inject credentials. Common agent credential directories and
session logs are cleared before committing the stopped builder to the immutable
image catalog. Supply credentials only after creating a working VM. An existing
image name is refused before creating a builder. A setup failure retains its
builder for inspection and reports its name; destroy that VM when finished.

## Detached agents and commands

```sh
# Store a runtime credential through the existing secret CLI, then refer to it.
# Agent credentials may also be supplied with --env-file.
husker prompt project 'Implement the task and run its tests' \
  --secret OPENAI_API_KEY=agent-key

# The result contains session.id. Keep it to reconnect from another client.
husker session project list
husker session project get SESSION_ID
husker events project SESSION_ID --follow

# Any noninteractive command can run as a detached session.
husker session project start --workdir /workspace --timeout 3600 -- \
  runuser -u developer -- sh -c 'cargo test'

husker session project cancel SESSION_ID
husker session project remove SESSION_ID --yes
```

`prompt` runs as `developer`, defaults to Codex, and accepts `--agent claude`.
The prompt is passed as one argument. It starts immediately and returns a session
ID; following its events is a separate operation. Interrupting `events --follow`
detaches the viewer. Cancellation kills the command's process group, including
nested tools. Sessions are noninteractive: stdin is closed, and approvals that
require an interactive terminal cannot be answered through this interface.

Logs and outcomes live under `/var/lib/husker/sessions` on the guest disk.
Arguments and environment are not stored in session metadata; command output can
still contain anything the executed program prints. There are at most 16 running
and 128 retained sessions per VM. Each log retains up to 4 MiB of raw output or
4,096 chunks, whichever comes first, while continuing to drain excess output.
`output_truncated` records truncation. Remove finished sessions to free retention
slots. The daemon's execution policy and timeout ceiling apply to sessions too.

For automation, `--output json events ... --after CURSOR` returns a page of
base64 stdout/stderr events, `next_cursor`, and `has_more`. Cursors start at 1;
pass the last consumed sequence to reconnect without replaying earlier output.

An active session pins the VM against idle suspension while the daemon can monitor
it. An explicit Firecracker suspend still pauses it; monitoring waits for resume
and releases its idle guard while suspended so the configured suspend TTL applies.
If the guest stays unreachable for 30 seconds while the VM reports running, the
monitor releases its idle guard and emits a warning. Accepted starts transfer the start/monitor handoff to the daemon, so cancelling
the HTTP request does not cancel it. Guest session RPCs have a 10-second transport
deadline. A timed-out start may already have been accepted: list sessions before
retrying to avoid duplicate commands. Client disconnects do not stop the command. Guest-agent restart marks unfinished sessions interrupted;
stop/reboot/VM destruction do not preserve live processes. Completed logs survive
agent restarts while the disk remains available. Empty unpublished start
transactions are recovered on restart; incomplete records with retained output
are preserved for inspection. Status publication is atomic and synced to disk.
The daemon logs session start/outcome audit events without storing arguments or
environment values in those events. Prometheus exposes
`husker_detached_sessions_total` and `husker_preview_connections_total`.

## Private application previews

```sh
husker session project start --workdir /workspace --timeout 3600 -- \
  python3 -m http.server 3000 --bind 127.0.0.1
husker preview project 3000
```

Open the printed `http://127.0.0.1:PORT/` URL. `--local-port` selects a stable
client port; the default allocates one. Keep the preview command running and use
Ctrl-C to close it. Each browser connection gets an authenticated binary WebSocket
to the daemon and a vsock connection to **guest loopback**. HTTP paths, queries,
and application WebSockets travel unchanged. No daemon bearer token is added to
application requests or URLs. A live preview connection pins the VM active,
including while an application is waiting to respond and until the last queued
response frame is delivered. Independent read/write pumps and bounded queues
prevent a guest that writes before reading from deadlocking the relay. Each CLI
preview accepts at most 64 concurrent relays; the daemon allows 128 preview
connections in total, with 64 KiB maximum WebSocket messages and frames.

The local listener is accessible to other processes on the client machine, like
an SSH local forward. Use application authentication where needed. Remote daemon
transport should use an SSH context or HTTPS. This command provides a private
local preview, not a public hostname or hosted HTTPS ingress. Existing preview
connections may close on suspend; reconnect after resume.

## Python client

The `husker` Python package now includes a standard-library synchronous SDK as
well as the native CLI wrapper. From a source checkout, imports work directly;
build/install the updated Python distribution to use it elsewhere. It never
starts a daemon or implicitly deletes a VM.

```python
import os
from husker import Client

client = Client("http://127.0.0.1:7777", token=os.environ.get("HUSKER_TOKEN"))
vm = client.create("sdk-project", image="dev-v1", mem_size_mib=4096,
                   vcpu_count=2, disk_size=20 * 1024**3)
session = vm.start(["sh", "-c", "printf hello; sleep 2; printf done"],
                   workdir="/workspace")
print(session.id)  # Save this before disconnecting.

# Another process can reattach with the same VM/session identifiers.
reattached = client.connect("sdk-project").session(session.id)
for event in reattached.iter_events(after=0):
    print(event.stream, event.sequence, event.data)  # data is bytes
print(reattached.wait().exit_code)
vm.destroy()  # Explicit cleanup.
```

`Sandbox` supports buffered exec, readiness probes, bounded file reads/writes,
streaming uploads/downloads, session start/list,
suspend/resume, fork, and explicit destruction. `Session` supports status,
cursor pages/iteration, wait, cancellation, and removal. HTTP errors expose
`status`, `kind`, and `hint`, with typed subclasses for authentication, policy,
missing resources, conflicts, capacity, and unsupported capabilities. The client
verifies TLS and refuses redirects to avoid forwarding daemon credentials.

`vm.wait_ready(["curl", "--fail", "http://127.0.0.1:3000/health"])` waits for
application readiness; its default `true` probe only establishes guest execution
readiness. Use an application probe before capturing a warm snapshot. Readiness
retries transient transport failures and unsuccessful probes within a deadline;
authentication and policy errors fail immediately.

For large binary files, consume `vm.iter_file(path)` into a binary destination or
call `vm.upload(path, binary_source)`. These transfer bounded chunks without
holding the entire file in memory. Downloads compare size and modification time
across ranges and reject changes or unavailable metadata. A failed transfer may
leave a partial destination. Uploads never retry a write automatically.

VM options use HTTP API field names. SDK creation does not run the `dev new`
Docker startup/check adapter. Use the CLI for that convenience workflow, SSH
context management, and local preview forwarding. For SDK access through SSH,
establish a local forward explicitly and pass its HTTP origin to `Client`.

## Restore and backend guarantees

| Capability | Linux / Firecracker | Linux / QEMU | macOS / Apple VZ |
| --- | --- | --- | --- |
| Development image, sessions, private previews | Available with guest agent v5 | Available with guest agent v5 | Available with guest agent v5 |
| Full-state suspend/resume | Available | Unsupported | Unsupported |
| Warm fork and pools | Available | Unsupported | Unsupported |
| Fork disk isolation | Own rootfs clone; attached volumes refused | — | — |
| TCP/vsock continuity through suspend | Clients must reconnect | — | — |

A fork owns its disk, TAP and vsock socket. The resumed source and multiple forks
can coexist. Persisted egress restrictions are validated before allocation and
installed while the fork's TAP is disconnected; a failure rolls back without
network exposure. An explicitly persisted empty policy stays deny-all.

Forks require guest agent v5 and a **bound VMGenID kernel driver**. The microVM
kernel build enables `CONFIG_VIRT_DRIVERS=y` and `CONFIG_VMGENID=y`, and rejects a
configuration that drops VMGenID. Rebuild existing kernels as well as guest images
before using the stricter fork path. Firecracker emits a new generation identifier
on restore; the Linux driver reseeds the kernel CRNG. This does not reset random
state, cached credentials, IDs, or external connections inside user applications.
Warm templates should establish application readiness before capture and avoid
capturing credentials or application entropy caches. See Firecracker's
[clone entropy guidance](https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/random-for-clones.md).

Current agents also reconcile the guest realtime clock with the host on fork and
resume. Monotonic timers are left unchanged. Resume remains compatible with older
guests and logs a warning if clock correction is unavailable. The live proof
checks wall-clock drift and monotonic timer behavior, rather than assuming a
restored VMM is sufficient evidence.

Nether's native Hypervisor.framework snapshot backend and surviving egress relay
are useful architectural references. Husker currently has neither a Nether
backend nor a relay that preserves upstream TCP through VMM termination. Apple
VZ cannot gain those capabilities through the guest-agent changes alone; adding a
new VMM backend requires its own isolation, compatibility and live-runtime gates.
See Nether's [forking contract](https://github.com/justinGrosvenor/nether/blob/main/docs/forking.md).

## Validation

Run ordinary socket/contract tests without a VM:

```sh
cargo nextest run -p husker -p husker-api -p husker-core -p husker-agent \
  -p husker-agent-proto --no-default-features
make test-sdk
make mutation-gate
```

The live proof is opt-in and requires an existing test daemon with Firecracker,
the updated guest agent, a prepared development image, and a container-capable
kernel with VMGenID. It creates uniquely named VMs, verifies reconnect,
cancellation, preserved warm-service PIDs, independent RAM counters and disks,
kernel entropy divergence, monotonic timers, wall clocks, resumed sessions,
VMM-process release while suspended, and private preview HTTP, then destroys
only the VMs it created. It does not install or restart a daemon:

```sh
HUSKER_RUN_DEV_E2E=1 HUSKER_DEV_E2E_URL=http://127.0.0.1:7777 \
  HUSKER_DEV_E2E_IMAGE=dev-v1 make test-dev-e2e-gated
```

The JSON result reports `fork_api_ms` and `first_guest_response_ms` separately
for every clone. These include Husker orchestration and client/agent overhead;
they are not raw VMM benchmarks. `HUSKER_DEV_E2E_FORKS` selects 1–8 clones (default
2). Ensure the test host can accommodate their configured 4 GiB / 2-vCPU limits
and disk clones. Local proof-workload tests validate the harness only; real
Firecracker, Ubuntu provisioning and kernel behavior require the live gate.

Set `HUSKER_DEV_E2E_TOKEN` for an authenticated daemon. Local tests do not establish
that the Ubuntu recipe, Docker, or full-state restore works on a particular host;
the live gate verifies those runtime boundaries. Browser automation and a
streamed desktop are subsequent features; this milestone establishes their
session and guest-local transport foundations.
