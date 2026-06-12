# Changelog

All notable changes to this project are documented in this file.

## [0.4.8] - 2026-06-12

### Added

- **Cloud-image VMs on macOS (Apple Silicon).** `husker run --cloud-image
  ubuntu.img` now works on the Apple VZ backend: EFI boot with a per-VM
  variable store, automatic qcow2-to-raw conversion via `qemu-img`, a
  cloud-init seed with the embedded aarch64 agent and SSH keys, DHCP via the
  VZ NAT NIC, and agent-reported guest IPs. `--volume`, services, and
  `--balloon` with cloud images are rejected on macOS for now; Intel Macs are
  unsupported.
- **Memory balloon on Apple VZ.** `--balloon` attaches a virtio balloon
  device on macOS and `husker balloon <vm> <mib>` resizes it, at parity with
  the Firecracker and QEMU backends. Platform caveat: explicit targets
  reclaim memory, but memory freed inside the guest is not automatically
  returned to the host.
- **Modules-free microVM kernel.** Default images now ship a from-source
  Linux 6.12 kernel with every required driver built in (no loadable
  modules), built by `guest/build-microvm-kernel.sh`. Kernel/initramfs
  version pairing can no longer break, guests boot with or without an
  initramfs (`root=/dev/vda` is added automatically when no initrd is used),
  and agent-ready boot time on Firecracker drops about 3.5x (19.7s to 5.6s
  measured). The 128 MiB default VM memory is sufficient on all boot paths.
- **Guest agent memory self-limit.** The agent confines itself to a cgroup
  v2 leaf with a 128 MiB `memory.high` throttle at startup; exec, job, and
  userdata workloads are moved out of the leaf so they never inherit the
  limit.

### Fixed

- **Apple VZ disk attachments no longer corrupt sparse raw images on APFS.**
  All VZ disk images attach with explicit cached + fsync modes; the default
  modes returned zeros for evicted page re-reads, causing random guest
  failures 30-150s after boot.
- **`make update-rootfs` no longer fails silently.** The debugfs injection
  runs as a single session and verifies the injected files by reading them
  back and comparing against the sources.
- **Gated e2e suite runs on standard hosts.** `HUSKER_RUN_IGNORED_E2E=1`
  tests resolve fixtures via the production default-image paths (arch and
  data-dir aware, env-overridable), create and clean up their own VMs with
  self-healing pre-delete, and now exercise both Firecracker and Apple VZ.
- **The initramfs device wait is a real timeout.** The `/dev/vda` poll
  sleeps between iterations (5s budget) instead of busy-spinning, and a
  boot-critical module that is present but fails to load produces an
  explicit kernel/module mismatch warning.

## [0.4.7] - 2026-06-11

### Added

- **CLI Spec v0.2 compliance (24/24).** New `schema` subcommand emitting the
  clispec v0.2 contract (global args, typed command args, output fields,
  error kinds with exit codes, mutation markers), a three-valued
  `--output/-o` flag (auto/text/json) with auto-JSON when piped, structured
  error envelopes as the last line of stderr, `--yes` confirmation gates for
  destructive commands without a TTY, and `--limit/--offset/--fields` with
  item-envelope pagination on list commands.

## [0.4.6] - 2026-06-11

### Added

- **`husker volume get <name>`.** Volume details (name, size, backing file,
  creation time) as text or JSON, mirroring `secret get`. The CLI schema
  annotates it read-only with `status`/`action`/`volume` output fields.

### Fixed

- **Cloud-image and QEMU runs no longer require Firecracker on the client.**
  `husker run --cloud-image ...` (or `--vmm qemu`) failed client-side when the
  Firecracker binary was missing, even though the request is served by QEMU.
  The preflight now only runs for Firecracker-bound requests.
- **Volume-backed services are limited to one instance.** Creating or scaling
  a service with `--volume` and more than one instance is now rejected with a
  clear error. Volumes are exclusive-attach, so previously only the first
  replica could start while the reconciler retried the rest forever.

## [0.4.5] - 2026-06-10

### Added

- **Bridged LAN networking for cloud-image VMs (Linux).** With a host bridge
  configured (`lan_bridge` / `HUSKER_LAN_BRIDGE`), `husker run --cloud-image
  ... --net bridged` puts the VM's NIC directly on that bridge: the guest gets
  its address via the LAN's DHCP (cloud-init), making it a first-class LAN
  citizen. Bridged VMs reject port forwards (they are on the LAN already);
  microVMs stay NAT-only for now. `husker info` reports the network mode, and
  `config check` verifies the configured bridge exists.

### Fixed

- **Guest-initiated shutdown is now detected on macOS.** The Apple VZ backend
  queries the live virtual-machine state, so a guest that powers itself off
  shows `stopped` in `husker list`/`info` and `wait` fails fast, matching the
  Linux backends.

## [0.4.4] - 2026-06-10

### Added

- **Persistent volumes.** `husker volume create data --size 10G` makes a named,
  host-side ext4 disk; `--volume data` on `run`/`job`/`service create` attaches
  it as the VM's second disk (`/dev/vdb` in both boot modes). Volumes survive
  VM destruction, exactly one VM may hold a volume at a time, deletion is
  refused while attached (409), and the service reconciler reattaches the
  volume to replacement instances - stateful services on ephemeral VMs.
- Cloud-image VMs auto-mount an attached volume at `/data` via cloud-init
  (`nofail`); microVM guests mount `/dev/vdb` themselves.
- `husker volume list/delete`, volume display in `info`/`service get`, a
  `volume` profile key, and an `mkfs.ext4` check in `config check`.

## [0.4.3] - 2026-06-10

### Added

- **Cloud-image services.** `husker service create --cloud-image <name|path>`
  runs a self-healing pool of stock cloud-image VMs (with `--disk-size`), no
  custom rootfs needed. A guest that powers itself off is replaced by the
  reconciler; note that under QEMU a guest `reboot` reboots in place, so
  ephemeral-style instances should `poweroff`.
- **Opt-in memory balloon.** `--balloon` on `run`/`job`/`service create`
  attaches a virtio balloon; `husker balloon <vm> <mib>` resizes it at runtime
  (`amount` = MiB reclaimed from the guest, deflate with 0). Supported on
  Firecracker and QEMU; VMs created without the flag get a clear error. The
  microVM initramfs now ships `virtio_balloon` (included in the next images
  release; existing downloaded images need a refresh for ballooning microVMs).
- The service API/CLI surface (`service get`, responses) reports cloud image,
  disk size, and balloon settings; profiles gain a `balloon` key.

## [0.4.2] - 2026-06-10

### Added

- **`husker job` - one-shot VM jobs.** Boot a VM, run a single command, print
  its output, destroy the VM, and exit with the guest command's exit code:
  `husker job --cloud-image ubuntu-2404 -- sh -c 'make test'`. Progress lines
  go to stderr so stdout carries exactly the command's output; `--keep`
  preserves the VM for debugging, Ctrl-C cleans up, and `--output json` emits
  a single structured result.
- **Named VM profiles.** `[profiles.<name>]` sections in the config file
  (cloud_image/rootfs/kernel/initrd/cpus/memory/disk_size/ssh_keys/vmm/env)
  applied with `--profile <name>` on `run` and `job`; explicit flags always
  win. `husker config check` validates each profile.
- **Per-request exec timeouts.** `husker exec --timeout <secs>` (and the job
  default of 3600s) raise the command execution bound beyond the daemon's 30s
  default, clamped by the new `exec_timeout_max_secs` config option (default
  3600, env `HUSKER_EXEC_TIMEOUT_MAX_SECS`).
- **More `/v1/metrics` gauges:** `husker_build_info{version}`,
  `husker_vms_stopped`, `husker_vms_failed`, and per-service
  `husker_service_desired_instances` / `husker_service_current_instances`.

## [0.4.1] - 2026-06-10

### Fixed

- **Guest-initiated shutdown is now detected at runtime.** A guest that powers
  itself off or reboots (an ephemeral CI runner finishing its job, or `poweroff`
  inside a cloud VM) used to leave a defunct VM process and a stale `running`
  state forever; the service reconciler never replaced such instances, so a
  runner pool deadlocked after its first job. The reconciler now verifies each
  instance against the live process (reaping exited children) before deciding,
  and `husker list` / `info` / `wait` report `stopped` instead of lying -
  `wait` on a dead VM fails fast with a clear error rather than polling to its
  timeout. Linux backends (Firecracker/QEMU) only; Apple VZ does not yet detect
  self-terminated guests.

## [0.4.0] - 2026-06-10

### Added

- **Cloud-image boot (UEFI/OVMF).** `husker run --cloud-image <name|path>` boots a
  stock cloud image (e.g. Ubuntu 24.04 qcow2) as a full UEFI VM on the QEMU/KVM
  backend: copy-on-write qcow2 clone, optional `--disk-size 10G` grow (cloud-init
  expands the filesystem on first boot), per-VM OVMF variable store, and the
  image's own bootloader - no custom kernel or rootfs build required.
- **Self-contained cloud-init seed with the husker agent inside.** husker generates
  the NoCloud seed itself (new `husker-cloudinit` crate, no genisoimage/cloud-localds
  dependency) and injects the guest agent plus a static network config, so the whole
  existing control plane - `exec`, `cp`, `shell`, `wait`, `--userdata`, `logs`,
  services - works on cloud VMs unchanged over vsock. The agent is embedded in the
  daemon binary at build time (`make build-with-agent`; release Linux binaries ship
  with it).
- **SSH key injection.** Repeatable `husker run --ssh-key <path.pub>` authorizes
  keys for the image's default user via cloud-init (cloud-image VMs only).
- **Cloud images in the image catalog.** `husker image import <name> --source x.img
  --kind cloud-image` registers a qcow2 image (validated by magic bytes), and
  `--cloud-image <name>` resolves it by name; a direct path still works. Image
  listings and the API now report the image kind.
- **Boot-mode-aware readiness timeouts.** UEFI/cloud VMs boot slower than microVMs,
  so `husker wait`, the exec agent-connect default, and userdata execution now
  default to 180s for them (microVM defaults unchanged).
- **OVMF and disk-size configuration.** New `ovmf_code` / `ovmf_vars` /
  `default_disk_size` config options (env: `HUSKER_OVMF_CODE`, `HUSKER_OVMF_VARS`,
  `HUSKER_DEFAULT_DISK_SIZE`); `husker config check` verifies the OVMF firmware and
  `qemu-img` when relevant.
- `husker info` shows the VM's boot mode, kernel, and source image/rootfs; the
  VM API response carries `boot_mode`, `kernel_path`, and `rootfs_path`.

### Changed

- `kernel_path` / `rootfs_path` in the create-VM API are now optional (required
  only for direct-kernel boot). Cloud VMs persist the resolved source image path
  as provenance instead of fake kernel/rootfs values.

### Fixed

- SSH keys containing control characters are rejected when the seed is built
  (cloud-init YAML injection guard), and invalid keys submitted through the API
  return 400 instead of 500.

## [0.3.2] - 2026-06-09

### Added

- **Configurable CID base** (`cid_base` config / `HUSKER_CID_BASE` env, default 3).
  Two husker daemons on one host can now be given distinct bases so they hand out
  disjoint vsock CIDs and TAP device names, completing multi-daemon coexistence
  alongside the per-bridge nftables tables from 0.3.1.

### Fixed

- **Reap orphaned QEMU processes on daemon startup.** When a daemon exits without
  cleanup (SIGKILL/OOM), the VM processes it left behind are now killed on the
  next start - matched by the persisted pid plus a live `qemu-system` check, so a
  recycled PID is never touched - instead of lingering and holding their vsock CID.

### Changed

- Agent readiness in the QEMU end-to-end test is verified with a real ping/pong
  round trip; `LinuxVsockStream` forwards vectored writes to the inner stream.

## [0.3.1] - 2026-06-09

### Added

- **QEMU/KVM backend (Linux).** A second `VmmBackend` runs full VMs via
  `qemu-system` (q35, virtio-over-PCI, vhost-vsock) alongside Firecracker. Raw
  ext4 rootfs (`format=raw,if=virtio`); the guest kernel must support
  `CONFIG_VIRTIO_PCI`. `husker config check` verifies `qemu_bin`, `/dev/kvm`, and
  `/dev/vhost-vsock` when QEMU is selected.
- **Per-VM backend selection.** One daemon can run Firecracker microVMs and QEMU
  full VMs side by side. `husker run --vmm <firecracker|qemu>` chooses the backend
  per VM (default: the daemon's configured `vmm` / `HUSKER_VMM`); the chosen
  backend is recorded and reported by `husker list` and `husker info`.
- **`husker wait <name>`** blocks until a VM's guest agent is ready, backed by a
  fast `GET /v1/vms/{name}/ready` probe. Agent readiness is verified with a real
  ping/pong round trip and a bounded timeout, so `exec`/`shell` immediately after
  boot no longer race the agent bind.
- **`husker logs --source <serial|boot|userdata>`** selects the log stream
  (default `serial`; `--userdata` retained as an alias).

### Changed

- **nftables tables are namespaced per bridge** (`husker_<bridge>`), so two husker
  daemons on one host no longer clobber each other's NAT.
- On a failed VM boot, the error now includes the tail of the guest serial log and
  the backend boot log (e.g. a kernel panic such as `Cannot open root device`),
  instead of only a generic startup-timeout message. The backend process log is
  standardized as `{id}.boot.log`.

## [0.3.0] - 2026-06-09

### Added

- **Service reconciler.** `husker service` is now a real managed-workload
  primitive. A service carries a VM template, and the daemon keeps
  `desired_instances` VMs running, automatically replacing instances that stop or
  fail. Instances are ordinary VMs named `<service>-<N>` and work with
  `husker list`/`exec`/`logs`/`cp`.
  - `husker service create` takes a full instance template: `--image`/`--rootfs`,
    `--kernel`, `--initrd`, `--vcpus`, `--memory`, `--userdata`, `--env`
    (plus `--instances`, `--host-group`).
  - `husker service scale` (including scale-to-zero to pause a workload) and
    `husker service delete` now create and destroy the underlying VMs.
  - `husker service get` lists each instance's name, ordinal, and state;
    `husker service list` shows running/desired counts.
  - A periodic self-healing reconciler runs in the daemon, configurable via the new
    `[service]` config (`reconcile_interval_secs`, `enabled`) and the
    `HUSKER_SERVICE_RECONCILE_INTERVAL` / `HUSKER_SERVICE_RECONCILE_ENABLED`
    environment variables.
- **Machine-readable CLI contract.** `husker schema` emits the full
  command/argument/output-field/exit-code contract for agent introspection, with
  structured exit codes (1 general, 2 not-found, 3 conflict, 4 denied,
  5 daemon-unreachable; `exec`/`shell` pass through the guest exit code) and a
  stable `code` field in `--output json` errors.
- `husker exec` gains `--env KEY=VALUE` and `--connect-timeout`; `husker run`
  accepts a bare image name; userdata output is captured and viewable with
  `husker logs <vm> --userdata`.
- The guest configures `eth0` from the kernel `ip=` cmdline at boot, and the guest
  agent now reports a clear message when a vsock bind fails due to missing kernel
  modules.
- `husker` warns once when a rootfs clone falls back to a full copy because the
  filesystem lacks reflink/copy-on-write support.

### Fixed

- Serial-log error codes are preserved; the newly structured userdata error codes
  no longer overwrite them.

## [0.2.1] - 2026-06-08

### Fixed

- Destroying a VM that produced no serial output no longer logs a spurious
  "failed to remove serial log" warning during cleanup.

### Internal

- Stabilized the `run_userdata` integration tests under parallel (nextest)
  execution by serializing them across processes, so they no longer
  intermittently clobber a shared host path.

## [0.2.0] - 2026-06-05

### Changed (BREAKING)

- Renamed the project from `shuck` to `husker` (the old name collided with an
  existing shell linter). The binary, crates, Python package, env vars, and
  data directories all change. There is no automatic migration.

  One-time migration for existing installs:

      mv ~/.local/share/shuck ~/.local/share/husker
      mv ~/.config/shuck      ~/.config/husker
      sudo mv /var/lib/shuck  /var/lib/husker      # if used
      sudo mv /etc/shuck      /etc/husker          # if used
      # Linux host networking: drop stale kernel state
      sudo nft delete table ip shuck   # recreated on next run
      sudo ip link del shuck0          # old default bridge, if present
      # systemd: replace contrib/shuck.service with contrib/husker.service

  All `SHUCK_*` environment variables are now `HUSKER_*`.

## [0.1.4] - 2026-04-21

### Added

- `SHUCK_API_URL` environment variable for pointing CLI commands at a
  remote daemon without `--api-url` on every call.
- `shuck run` now logs which kernel, rootfs, and initrd were selected
  before it POSTs to the daemon, making first-run debugging easier.

### Fixed

- `SHUCK_DATA_DIR` now cascades to `default_kernel`, `default_rootfs`,
  and `default_initrd` unless those are set explicitly, so relocating
  the data dir no longer requires overriding four separate variables.
- Linux data dir falls back to the XDG data home (`~/.local/share/shuck`)
  when `/var/lib/shuck` is not writable, so `pip install --user`-style
  flows work without `sudo`.
- Daemon now resolves `firecracker_bin` from `{data_dir}/bin/` when it
  is neither absolute nor on `PATH`, so the auto-installed binary is
  picked up on first run.
- Daemon-connect errors now include the URL and a hint to start the
  daemon, instead of a bare hyper error.
- Exec requests issued right after `shuck run` retry against the guest
  agent with exponential backoff, eliminating the first-boot 503 race.
- Alpine rootfs no longer floods the serial log with `hvc0` open
  errors on Firecracker guests — the getty line now guards on
  `[ -c /dev/hvc0 ]`. Apple VZ guests still get their serial console.

## [0.1.3] - 2026-04-21

### Added

- POSIX installer script: `curl -sSfL https://raw.githubusercontent.com/rvben/shuck/main/install.sh | sh`. Verifies SHA-256, respects `SHUCK_VERSION` and `SHUCK_PREFIX`.
- Homebrew tap publishing: releases now push `rvben/homebrew-tap/Formula/shuck.rb` so `brew install rvben/tap/shuck` works.
- `shuck run` prompts on a TTY to download Firecracker when it's missing from `PATH`; non-interactive callers (CI, scripts) keep using `SHUCK_AUTO_INSTALL_FIRECRACKER=1`.
- `SECURITY.md`, `CONTRIBUTING.md`, issue and pull-request templates; README gains alternatives, security, and troubleshooting sections.

### Fixed

- Compile with `--no-default-features` on Linux: the daemon start path no longer reaches for the macOS-gated `shuck_vmm::apple_vz` module, so `make test-contracts` builds cleanly on Linux.
- Rust 1.95 compatibility: `openpty` winsize pointer uses `addr_of_mut!` to satisfy the `unnecessary_mut_passed` clippy lint without breaking BSD/macOS signatures.
- Graceful-shutdown CI drill: pre-builds the daemon outside the health-check window and pins `RUST_LOG` so the `shuck_api` shutdown log is captured.

## [0.1.2] - 2026-04-21

### Fixed

- `shuck images pull` now resolves the latest `images-YYYY-MM-DD` release via the GitHub API instead of `releases/latest/download`, which GitHub redirects to the highest semver tag and therefore skipped over the image releases once v0.1.1 shipped. Pinning `images_base_url` at a `.../releases/download/<tag>` URL still short-circuits the resolver.

## [0.1.1] - 2026-04-21

### Fixed

- `shuck images pull` (plural) now resolves — the `image` subcommand carries visible aliases `images` and `img`, matching the README and the wording used in `shuck run`'s missing-default-image error hints.

## [0.1.0] - 2026-04-20

First release where `pip install shuck && shuck run` works without bring-your-own kernel or rootfs.

### Added

- `shuck images pull` subcommand that fetches the latest signed kernel, initramfs, and rootfs from the `images-YYYY-MM-DD` GitHub Releases and verifies SHA-256 digests.
- `shuck run` now falls back to the pulled default rootfs, kernel, and initramfs when `--rootfs` is omitted, with actionable hints if they are missing.
- Firecracker auto-install on Linux when `firecracker` isn't on `PATH` — downloads the pinned release tarball into the data dir on first use.
- Arch-aware guest agent + rootfs build pipeline: `make build-agent-aarch64`, arch-suffixed initramfs, and a reproducible Alpine rootfs with `shuck-agent` baked in.
- `build-images.yml` workflow that builds and publishes the default image set monthly (or on manual dispatch).
- `default_rootfs`, `default_initrd`, and `images_base_url` Config fields with env-var overrides.
- API policy controls for exec/file operations (allowlists, denylists, timeouts, payload limits).
- Sensitive endpoint rate limiting and Prometheus-style metrics endpoint.
- Request correlation IDs (`x-request-id`) in API middleware/logs.
- Startup reconciliation for persisted Linux port forwards.
- Shared Firecracker vsock CONNECT handshake helper.
- CLI `--output json` mode for command responses.
- OpenAPI contract tests and perf baseline test.
- Core failure-injection lifecycle tests.
- CI lanes for contracts, coverage, perf baseline, graceful shutdown drill, and gated ignored e2e suites.
- Nightly quality workflow for chaos/perf/soak checks.
- Security, operations, ADR, compatibility, performance, testing, release, and debt register docs.

### Changed

- README quickstart rewritten around `pip install shuck` + `shuck images pull`; BYO kernel/rootfs moved to a secondary section.
- API error envelope standardized with machine-readable fields (`code`, `message`, `hint`, `details`) while retaining `error` alias.
- Log follow handling hardened for truncation/rotation behavior.
- `shuck doctor` strengthened to flag missing default images and kernel/initrd mismatches.
