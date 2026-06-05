# Husker

An open-source microVM manager built on [Firecracker](https://firecracker-microvm.github.io/) (Linux) and [Apple Virtualization.framework](https://developer.apple.com/documentation/virtualization) (macOS).

- Boot lightweight VMs in milliseconds
- Execute commands, transfer files, open interactive shells
- Stream serial console logs
- Port forwarding with nftables NAT (Linux)
- REST API + CLI
- Cloud-init style userdata scripts

## Status

Pre-1.0. The core feature set works and has test coverage, but:

- The HTTP API, CLI flags, config schema, and on-disk state layout may change without a deprecation period.
- The Linux/Firecracker backend is more mature than the macOS/Apple VZ backend.
- It has not been run at scale or under production workloads.
- Security features (token auth, rate limiting, encrypted secrets) exist but have had limited review. Don't expose the daemon to an untrusted network.

Useful for experimentation, local development, and CI. Not recommended for production.

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

On Linux, `husker run` needs `firecracker` on `PATH`. If it's missing, husker prompts to download a pinned release into the data directory. For non-interactive use (CI, scripts), set `HUSKER_AUTO_INSTALL_FIRECRACKER=1` to skip the prompt.

`husker images pull` fetches the latest signed image set from the `images-*`
[GitHub Releases](https://github.com/rvben/husker/releases). If no image
release is published yet for this arch, the command will fail — use the
BYO path below in the meantime.

## BYO kernel / rootfs

If you want to use your own images, pass `--kernel` and the rootfs path:

```bash
husker run /path/to/rootfs.ext4 --kernel /path/to/vmlinux
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
| macOS ARM64 | Apple Virtualization.framework | Shared NAT (VZ-managed) | Experimental |

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
