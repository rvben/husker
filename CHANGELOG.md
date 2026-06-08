# Changelog

All notable changes to this project are documented in this file.

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
