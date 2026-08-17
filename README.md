# Husker

An open-source microVM manager built on [Firecracker](https://firecracker-microvm.github.io/) (Linux) and [Apple Virtualization.framework](https://developer.apple.com/documentation/virtualization) (macOS).

- Boot lightweight VMs in seconds (about 1s from a warm pool)
- Execute commands, transfer files, open interactive shells
- Stream serial console logs
- Port forwarding (nftables NAT on Linux, a userspace TCP proxy on macOS)
- REST API + CLI
- Cloud-init style userdata scripts

## Status

Pre-1.0. The core feature set works and has test coverage, but:

- The HTTP API, CLI flags, config schema, and on-disk state layout may change without a deprecation period.
- The Linux/Firecracker backend is more mature than the macOS/Apple VZ backend.
- It has not been run at scale or under production workloads.
- Security features (token auth, rate limiting, encrypted secrets) exist but have had limited review. Don't expose the daemon to an untrusted network.

Useful for experimentation, local development, and CI. Not recommended for production.

## Where Husker is useful

Husker works best as an execution plane beside your long-lived infrastructure:

- disposable sandboxes for risky agent or dependency-heavy commands;
- memory-isolated build offload with explicit artifact return;
- single-use CI runners replaced from a clean image after every job;
- scheduled scripts that need secrets and network access but no permanent host;
- trusted integration VMs that can reach private registries and test services;
- warm pools for repeated short tasks where cold-start latency dominates.

Keep databases, ingress, monitoring, and other durable services on the platform
already responsible for their state. Separate untrusted internet-only jobs from
trusted jobs that need private-network access instead of weakening one shared
boundary.

The [two-host homelab case study](docs/case-studies/homelab.md) documents these
patterns with observed build, runner, scheduler, boot, storage, and network
isolation evidence from a real deployment.

## Quick Start

### Install

macOS (Homebrew):

```bash
brew install rvben/tap/husker
```

Linux & macOS (installer script):

```bash
curl -sSfL https://raw.githubusercontent.com/rvben/husker/main/install.sh | sh
```

Cross-platform (PyPI):

```bash
pip install husker
```

Pinning a version: `curl -sSfL https://raw.githubusercontent.com/rvben/husker/main/install.sh | HUSKER_VERSION=v0.1.2 sh` or `pip install husker==0.1.2`.

### First boot

```bash
# Fetch the default kernel + rootfs for this host
husker images pull

# Start the daemon
husker daemon &

# Confirm it came up (checks the daemon, images, and backend)
husker doctor

# Boot a VM
husker run --name hello --cpus 2 --memory 512

# Interact
husker exec hello -- uname -a
husker shell hello
husker cp local.txt hello:/tmp/local.txt
husker logs hello -f

# Clean up
husker destroy hello
```

In text mode, `husker exec` streams stdout and stderr while the command runs.
`--output json` intentionally returns one complete result document after exit,
which keeps automation atomic and machine-readable. VMs using an older guest
agent remain compatible but buffer output until their image is refreshed.

On Linux, `husker run` needs `firecracker` on `PATH`. If it's missing, husker prompts to download a pinned release into the data directory. For non-interactive use (CI, scripts), set `HUSKER_AUTO_INSTALL_FIRECRACKER=1` to skip the prompt.

`husker images pull` fetches the latest image set from the `images-*`
[GitHub Releases](https://github.com/rvben/husker/releases) and verifies each
asset against the published `SHA256SUMS`. If no image release is published yet
for this arch, the command will fail - use the BYO path below in the meantime.

## BYO kernel / rootfs

If you want to use your own images, pass `--kernel` and the rootfs path:

```bash
husker run /path/to/rootfs.ext4 --kernel /path/to/vmlinux
```

## Hot Pools

A **pool** is a pre-warmed, suspended template VM that husker forks fresh,
isolated VMs from in about a second, instead of a 6-8s cold boot. Each fork
inherits the template's already-booted state (kernel up, guest agent running,
whatever you installed), so checkouts are fast and start from a known-good
baseline. Hot pools build on Firecracker's snapshot/restore (Linux).

```bash
# Create a pool: boots a template VM once, warms it, then suspends it.
husker pool create web --vcpus 2 --memory 512

# Fork a fresh, isolated VM out of the pool (~1s).
husker pool checkout web --name task-42
husker exec task-42 -- ./run-tests.sh
husker destroy task-42

# Inspect and tear down.
husker pool list
husker pool get web
husker pool delete web
```

A single pool can be checked out many times concurrently: each fork gets its own
IP, vsock CID, and copy-on-write rootfs, fully isolated from its siblings and
from the template (the template stays suspended and is never mutated).

`run` and `job` can draw straight from a pool with `--pool`, the fast path for
sandboxing untrusted or agentic work. The image and boot flags come from the
pool's template, so pass only `--name` (plus `job`'s `--sync-cwd`/`--out`) and
your command:

```bash
# One-shot: fork from the pool, run the command, then destroy the VM.
husker job --pool web -- make test

# Long-lived: fork from the pool instead of cold-booting.
husker run --pool web --name preview
```

## Configuration

Copy `config.example.toml` to one of the discovery paths:

1. `~/.config/husker/config.toml` (user)
2. `/etc/husker/config.toml` (system)

Or pass `--config /path/to/config.toml` explicitly. See `config.example.toml` for all available fields.

## Platform Support

| Platform | Backend | Networking | Status |
|----------|---------|------------|--------|
| Linux x86_64 | Firecracker | TAP + nftables NAT, port forwarding | Usable |
| macOS ARM64 | Apple Virtualization.framework | Shared NAT (VZ-managed), port forwarding (userspace proxy) | Experimental |
| Linux x86_64 | QEMU/KVM | TAP + nftables NAT, port forwarding | Experimental |

Intel macOS and Windows are not supported (Windows: use WSL2). Linux also
supports aarch64 (agent-less build - see below).

### Feature support by backend

| Feature | Firecracker (Linux) | QEMU (Linux) | Apple VZ (macOS) |
|---------|:---:|:---:|:---:|
| Direct-kernel boot | ✓ | ✓ | ✓ |
| Cloud images (`--cloud-image`) | — ¹ | ✓ (UEFI/OVMF) | ✓ (EFI) |
| `exec` / `shell` / file copy | ✓ | ✓ | ✓ |
| One-shot jobs (`husker job`) | ✓ | ✓ | ✓ |
| Self-healing services | ✓ | ✓ | ✓ ² |
| Persistent volumes (`--volume`) | ✓ | ✓ | ✓ ² |
| Host bind-mounts (`--mount`) | — | ✓ (virtiofs) | — |
| Memory balloon (`--balloon`) | ✓ | ✓ | ✓ |
| Bridged LAN (`--net bridged`) | — | ✓ ³ | — |
| Snapshots | ✓ | — | — |
| Fork / pool checkout | ✓ | — | — |
| Idle suspend / resume | ✓ | — | — |

Notes:
1. Cloud-image boot needs UEFI; Firecracker does direct-kernel boot only, so use `--vmm qemu` on Linux for cloud images.
2. On macOS, `--volume` and services are not yet supported together with `--cloud-image` (both work with the default rootfs).
3. Bridged networking requires a cloud-image VM (so `--vmm qemu`) plus the `lan_bridge` config option, and is Linux-only.

Only the two primary targets (Linux x86_64 and macOS ARM64) ship with the
embedded guest agent. The Linux ARM64 and Intel-macOS builds are agent-less:
`husker run` boots, but `exec`/`shell`/`cp` and cloud-image VMs need the agent, so
they will report the agent as unreachable. `husker doctor` flags a missing embedded
agent. Use a primary-target build for full functionality.

### QEMU/KVM backend (Linux)

Besides Firecracker microVMs, husker can run full QEMU/KVM VMs on Linux. Select it
with `vmm = "qemu"` in the config file or `HUSKER_VMM=qemu`. Requires `/dev/kvm`,
`/dev/vhost-vsock` (load the `vhost_vsock` kernel module), and `qemu-system-x86_64`
on `PATH` (override with `HUSKER_QEMU_BIN`).

Current scope is direct-kernel boot (same kernel + rootfs model as the Firecracker
backend), with the guest agent reachable over vsock. Cloud-image boot via UEFI/OVMF
is also supported - see the Cloud Images section below.

The QEMU backend also enables **host bind-mounts** via virtiofs: share a host directory
into the guest in real time with `--mount <host>:<guest>[:ro]`. See [docs/host-mounts.md](docs/host-mounts.md).

**Guest kernel requirement:** the QEMU backend uses the `q35` machine, which puts the
root disk, NIC, and vsock device on the PCI bus, so the guest kernel must have
`CONFIG_VIRTIO_PCI` (and an initramfs if `virtio_blk` is a module). The default husker
images satisfy this. Firecracker's own kernels are built for virtio-MMIO only and will
panic under QEMU with `Cannot open root device "vda"`. The husker default images and
most distro kernels work as-is.

### Cloud Images

husker can boot stock cloud images (Ubuntu, Debian, etc.) on both platforms:

- **Linux:** QEMU/OVMF (UEFI boot). Requires `ovmf_code` and `ovmf_vars` in config.
- **macOS (Apple Silicon):** Apple Virtualization.framework with built-in EFI.

#### macOS prerequisites

```bash
brew install qemu   # qemu-img is used for qcow2-to-raw conversion
```

#### Example (macOS)

```bash
# Download a cloud image (ARM64 for Apple Silicon)
curl -LO https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-arm64.img

husker run --name ubuntu \
  --cloud-image ubuntu-24.04-server-cloudimg-arm64.img \
  --ssh-key ~/.ssh/id_ed25519.pub
```

Networking uses VZ shared NAT; the guest gets a DHCP address in the `192.168.64.x`
range. The guest IP appears in `husker info ubuntu` once the agent reports it (typically
within 20-30 seconds of first boot). Connect with `husker shell ubuntu` or via SSH once
the IP is known.

**Not yet supported on macOS with cloud images:** `--volume`, `--mount`, `--balloon`, and services
(`husker service`). Bridged networking (`--net bridged`) is Linux-only.

## Alternatives

husker is one of several ways to run microVMs. Rough positioning:

| Tool | Backend | Focus | Notes |
|---|---|---|---|
| **husker** | Firecracker (Linux) + Apple VZ (macOS) | Single-host VM manager with a REST API and CLI | SQLite-backed state, port forwarding, guest agent over vsock. |
| [Ignite](https://github.com/weaveworks/ignite) | Firecracker | Docker-image-style workflow on Firecracker | Archived by Weaveworks; Linux only. |
| [firecracker-containerd](https://github.com/firecracker-microvm/firecracker-containerd) | Firecracker | containerd runtime backed by microVMs | Kubernetes-friendly; Linux only. |
| [krunvm](https://github.com/containers/krunvm) | libkrun | OCI-image microVMs on macOS | No daemon; ephemeral per-command VMs. |
| [Lima](https://github.com/lima-vm/lima) | QEMU (+ VZ on macOS) | Full Linux VMs as a dev environment | Heavier than Firecracker; broader guest support. |

Pick husker if you want Firecracker on Linux with a matching Apple VZ path on macOS, driven by a single CLI + daemon.

## Architecture

```
CLI (husker) ──> REST API (husker-api) ──> Core (husker-core)
                                           ├── VMM (husker-vmm)      Firecracker / Apple VZ
                                           ├── State (husker-state)  SQLite persistence
                                           ├── Net (husker-net)      TAP devices, IP allocation
                                           └── Storage (husker-storage) Rootfs cloning
                                       Guest Agent (husker-agent) ←── Proto (husker-agent-proto)
```

Host-guest communication uses vsock (port 52). Messages are length-prefixed JSON with base64-encoded binary payloads.

Once the daemon is running, the REST API is browsable at `http://127.0.0.1:7777/docs` (Swagger UI), with the raw OpenAPI schema at `/api-docs/openapi.json`.

## Security

- [Threat model](docs/security/threat-model.md) — STRIDE analysis and residual risks.
- [Hardening guide](docs/security/hardening-guide.md) — deployment posture and config recommendations.
- Report vulnerabilities privately via [GitHub Security Advisories](https://github.com/rvben/husker/security/advisories/new). See [SECURITY.md](SECURITY.md).

The daemon defaults to loopback-only. Don't bind it on a public interface without a bearer token and a terminating reverse proxy.

## Troubleshooting

**`husker run` can't find `firecracker` (Linux)**
On a TTY, husker prompts to download a pinned release. For scripted/CI use, set `HUSKER_AUTO_INSTALL_FIRECRACKER=1` to skip the prompt, or install Firecracker yourself from [the releases page](https://github.com/firecracker-microvm/firecracker/releases).

**`husker run` reports `kvm_init: permission denied` (Linux)**
Add your user to the `kvm` group: `sudo usermod -aG kvm $USER` and re-login.

**`husker run` fails on macOS with a virtualization entitlement error**
The binary needs the `com.apple.security.virtualization` entitlement. `pip`, `brew`, and the installer script all ship a codesigned binary. If you built from source, run `make install` — it ad-hoc signs via `husker.entitlements`.

**macOS: VM boots but exits immediately**
Apple VZ needs an initramfs to mount the rootfs. If you're using custom images, make sure `--initrd` points at a matching initramfs (see `guest/build-initramfs.sh`).

**`husker daemon` binds but the CLI can't connect**
The CLI defaults to `http://127.0.0.1:7777`. If the daemon listens elsewhere, pass `--api-url http://host:port` (and `--api-token` if auth is enabled).

**Rootfs edits don't take effect on macOS**
Use `make update-rootfs` to inject changes via `debugfs` (works in LXC and macOS). Loop-mounting doesn't work on macOS.

## Development

Requires Rust 1.90+ and cargo-nextest.

```bash
make build          # Debug build
make build-release  # Release build (LTO, stripped)
make build-agent    # Static musl agent for guest VMs
make test           # Full test suite
make test-unit      # Unit tests only
make lint           # fmt-check + clippy
make check          # Type check
make install        # Install (auto-detects macOS, signs binary)
```

### Running a Development VM

```bash
make run-daemon                     # Start daemon
make build-agent-aarch64            # Build ARM64 agent (macOS guests)
make update-rootfs                  # Inject agent into rootfs image
```

### Systemd

A systemd unit file is provided at `contrib/husker.service`.

## Contributing

Issues and pull requests welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the dev workflow and commit conventions.

## License

See [`LICENSE`](LICENSE).
