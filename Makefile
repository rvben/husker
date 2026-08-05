.PHONY: all build build-release build-agent build-agent-aarch64 build-with-agent build-release-with-agent build-release-macos sign-macos test test-unit test-macos test-e2e test-e2e-gated test-net-e2e-gated test-qemu-e2e-gated test-vz-cloud-e2e-gated test-idle-policy-e2e-gated test-oci-boot-e2e-gated test-suspend-fork-e2e-gated test-pool-e2e-gated test-contracts test-failure-injection test-perf-baseline coverage-ci mutation-gate graceful-shutdown-drill chaos-tests nightly-quality lint fmt fmt-check clippy clippy-macos check check-macos clean install install-restart run-daemon update-rootfs build-initramfs test-initramfs build-kernel-image build-rootfs build-k3s-rootfs build-k3s-kernel test-k3s build-microvm-kernel audit deny update-deps check-deps setup release-patch release-minor release-major post-release

# Target architecture for guest build targets (aarch64 = macOS VZ, x86_64 = Firecracker).
ARCH ?= aarch64
# Alpine Linux version used by build-initramfs.
ALPINE_VERSION ?= 3.21

# Optional, untracked local overrides. Kept out of git so a checkout can carry
# machine-specific settings without touching the repo.
-include Makefile.local

# Command run by post-release once the artifacts are published and the local
# install is updated, e.g. to roll the new version out to your own hosts. Empty
# by default, so a plain clone releases exactly as before; set it in Makefile.local.
POST_RELEASE ?=

all: lint test

# Build all crates (debug)
build:
	cargo build --workspace

# Build all crates (release)
build-release:
	cargo build --workspace --release

# Cross-linker defaults assume the prebuilt musl-cross toolchain from musl.cc.
# Override when building on distros that ship an aarch64/x86_64 cross-gcc instead
# (e.g. CI uses `gcc-aarch64-linux-gnu` because musl.cc is occasionally offline).
X86_64_MUSL_LINKER  ?= x86_64-linux-musl-gcc
AARCH64_MUSL_LINKER ?= aarch64-linux-musl-gcc

# Build only the guest agent (optimized for size, x86_64)
build-agent:
	CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=$(X86_64_MUSL_LINKER) \
	cargo build --package husker-agent --profile agent --target x86_64-unknown-linux-musl

# Build the daemon WITH the embedded guest agent (for cloud-image support).
# Requires the x86_64-musl target + linker (Linux/CI). The default `build` stays
# musl-free for the macOS dev loop; cloud-image support is opt-in via this target.
build-with-agent: build-agent
	HUSKER_EMBED_AGENT_BIN=$(CURDIR)/target/x86_64-unknown-linux-musl/agent/husker-agent \
		cargo build -p husker

# Release build of the daemon WITH the embedded guest agent (cloud-image support).
# Requires the x86_64-musl target + linker (Linux/CI). Release/CI for cloud-image
# support builds the agent first; see .github/workflows/release.yml.
build-release-with-agent: build-agent
	HUSKER_EMBED_AGENT_BIN=$(CURDIR)/target/x86_64-unknown-linux-musl/agent/husker-agent \
		cargo build --release -p husker

# Build guest agent for ARM64 (for macOS/VZ guests and VZ cloud-image seeds).
# On macOS, zig provides the musl cross linker (brew install zig; cargo install cargo-zigbuild).
build-agent-aarch64:
ifeq ($(shell uname -s),Darwin)
	cargo zigbuild --package husker-agent --profile agent --target aarch64-unknown-linux-musl
else
	CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=$(AARCH64_MUSL_LINKER) \
	cargo build --package husker-agent --profile agent --target aarch64-unknown-linux-musl
endif

# Build release for macOS (no linux-net, with entitlement signing).
# Embeds the aarch64-musl guest agent so Apple Silicon builds support VZ cloud images.
build-release-macos: build-agent-aarch64
	HUSKER_EMBED_AGENT_BIN=$(CURDIR)/target/aarch64-unknown-linux-musl/agent/husker-agent \
		cargo build --workspace --release --no-default-features
	$(MAKE) sign-macos

# Sign macOS binary with virtualization entitlement
sign-macos:
	codesign --entitlements husker.entitlements --force --sign - target/release/husker

# Check compilation without linux-net (macOS path)
check-macos:
	cargo check --workspace --no-default-features

# Run tests on macOS (without linux-net feature)
# Excludes husker-api; run its no-default-features suite via `test-macos-api`.
test-macos:
	cargo nextest run --workspace --no-default-features --exclude husker-api 2>/dev/null || cargo test --workspace --no-default-features --exclude husker-api

# Run husker-api tests on the macOS (no-linux-net) build. test-macos excludes
# husker-api, so this is the twin that exercises the cross-platform API surface
# (e.g. boot-mode and port-forward logic that has linux-net-gated counterparts).
test-macos-api:
	cargo nextest run -p husker-api --no-default-features 2>/dev/null || cargo test -p husker-api --no-default-features

# Run all tests
test:
	cargo nextest run --workspace 2>/dev/null || cargo test --workspace

# Run unit tests only (fast)
test-unit:
	cargo nextest run --workspace --lib 2>/dev/null || cargo test --workspace --lib

# Lint
lint: fmt-check clippy clippy-macos

# Check formatting
fmt-check:
	cargo fmt --all -- --check

# Format code
fmt:
	cargo fmt --all

# Clippy
clippy:
	cargo clippy --workspace --all-targets -- -D warnings

# Clippy the macOS/no-linux-net configuration, which CI checks on its macOS
# runners with RUSTFLAGS=-D warnings. The pass above builds with default
# features, so a function reachable only from a `linux-net`-gated caller looks
# used there and is dead code here. Without this, `make lint` goes green on a
# tree that fails four CI jobs.
#
# Darwin only: --no-default-features on Linux drops linux-net without enabling
# the macOS VZ backend in its place, leaving a configuration husker neither
# supports nor ships. The skip is printed rather than silent so a green lint on
# Linux is not read as having covered this.
clippy-macos:
ifeq ($(shell uname -s),Darwin)
	cargo clippy --workspace --no-default-features --all-targets -- -D warnings
else
	@echo "clippy-macos: SKIPPED on $(shell uname -s) (macOS-only configuration; CI covers it on its macOS runners)"
endif

# Type check without building
check:
	cargo check --workspace --all-targets

# Clean build artifacts
clean:
	cargo clean

# Install husker binary (auto-detects macOS to disable linux-net and sign).
# On macOS, builds the aarch64-musl agent first and embeds it for VZ cloud-image support.
install:
ifeq ($(shell uname -s),Darwin)
	$(MAKE) build-agent-aarch64
	HUSKER_EMBED_AGENT_BIN=$(CURDIR)/target/aarch64-unknown-linux-musl/agent/husker-agent \
		cargo install --path crates/husker --no-default-features
	codesign --entitlements husker.entitlements --force --sign - "$$(which husker)"
else
	cargo install --path crates/husker
endif

# Install and restart daemon (development workflow)
install-restart: install
	@pkill -f "husker daemon" 2>/dev/null || true
	@sleep 1
	@nohup husker daemon > /tmp/husker-daemon.log 2>&1 &
	@echo "Daemon restarted (log: /tmp/husker-daemon.log)"

# Run E2E tests (requires running daemon and a booted VM)
test-e2e:
	cargo nextest run --package husker --test e2e -- --ignored 2>/dev/null || cargo test --package husker --test e2e -- --ignored

# Run ignored husker e2e tests only when explicitly enabled.
#
# Required env vars (Linux):
#   HUSKER_RUN_IGNORED_E2E=1
#   HUSKER_E2E_KERNEL   path to vmlinux  (default: /var/lib/husker/kernels/vmlinux)
#   HUSKER_E2E_ROOTFS   path to rootfs   (default: /var/lib/husker/images/alpine-x86_64.ext4)
#   HUSKER_E2E_INITRD   path to initrd   (default: /var/lib/husker/kernels/initramfs-x86_64-virt.gz)
#
# Defaults point at images installed by `husker images pull`.
# A running `husker daemon` on 127.0.0.1:7777 is also required.
test-e2e-gated:
	@if [ "$${HUSKER_RUN_IGNORED_E2E:-0}" = "1" ]; then \
		cargo test --package husker --test e2e -- --ignored; \
	else \
		echo "Skipping husker ignored e2e tests (set HUSKER_RUN_IGNORED_E2E=1 to enable)"; \
		[ -n "$${GITHUB_ACTIONS:-}" ] && echo "::warning title=e2e gate not run::husker e2e tests were SKIPPED (HUSKER_RUN_IGNORED_E2E is not '1'); this job is green but exercised no e2e"; \
		true; \
	fi

# Run ignored husker-net e2e tests only when explicitly enabled.
# --test-threads=1 matches the suite's own documented contract: the tests mutate
# global host network state (the ip_forward sysctl, shared routing) and are run
# one at a time. Each test also uses a unique bridge/table name so a stray thread
# can never clobber another's nftables table.
test-net-e2e-gated:
	@if [ "$${HUSKER_RUN_NET_E2E:-0}" = "1" ]; then \
		cargo test --package husker-net --test e2e_bridge -- --ignored --test-threads=1; \
	else \
		echo "Skipping husker-net ignored e2e tests (set HUSKER_RUN_NET_E2E=1 to enable)"; \
		[ -n "$${GITHUB_ACTIONS:-}" ] && echo "::warning title=net e2e gate not run::husker-net e2e tests were SKIPPED (HUSKER_RUN_NET_E2E is not '1'); this job is green but exercised no e2e"; \
		true; \
	fi

# Real QEMU boot + vsock e2e (needs Linux KVM + vhost-vsock + qemu + a virtio-PCI
# kernel; the Firecracker/MMIO release kernel will NOT boot here).
test-qemu-e2e-gated: ## Real QEMU boot + vsock e2e (needs Linux/KVM/qemu + a virtio-PCI kernel)
	@if [ "$${HUSKER_RUN_QEMU_E2E:-0}" = "1" ]; then \
		HUSKER_RUN_IGNORED_E2E=1 cargo nextest run -p husker-vmm --run-ignored all qemu_boots_and_vsock; \
	else \
		echo "Skipping QEMU e2e (set HUSKER_RUN_QEMU_E2E=1; needs Linux/KVM/qemu/vhost-vsock + a virtio-PCI kernel via HUSKER_E2E_KERNEL/ROOTFS)"; \
		[ -n "$${GITHUB_ACTIONS:-}" ] && echo "::warning title=qemu e2e gate not run::QEMU e2e was SKIPPED (HUSKER_RUN_QEMU_E2E is not '1'); this job is green but exercised no e2e"; \
		true; \
	fi

# Gated Apple VZ cloud-image e2e (macOS only; needs qemu-img + a local Ubuntu arm64 image).
# Usage: HUSKER_VZ_CLOUD_IMAGE=/tmp/noble-arm64.img HUSKER_RUN_VZ_CLOUD_E2E=1 make test-vz-cloud-e2e-gated
test-vz-cloud-e2e-gated: ## Gated VZ cloud-image e2e (macOS only)
	@if [ "$${HUSKER_RUN_VZ_CLOUD_E2E:-0}" = "1" ]; then \
		cargo nextest run -p husker --no-default-features --run-ignored all vz_cloud; \
	else \
		echo "Skipping VZ cloud-image e2e (set HUSKER_RUN_VZ_CLOUD_E2E=1; macOS + qemu-img + HUSKER_VZ_CLOUD_IMAGE)"; \
		[ -n "$${GITHUB_ACTIONS:-}" ] && echo "::warning title=vz cloud e2e gate not run::VZ cloud-image e2e was SKIPPED (HUSKER_RUN_VZ_CLOUD_E2E is not '1'); this job is green but exercised no e2e"; \
		true; \
	fi

# Gated idle-policy suspend/resume-on-connect e2e on real Firecracker (Linux/KVM/
# Firecracker/root). Needs HUSKER_E2E_KERNEL/ROOTFS (the standard images-* release
# works here, unlike the QEMU gate). The test is #[ignore] + linux-net-only.
test-idle-policy-e2e-gated: ## Gated idle-policy suspend/resume e2e (Linux/KVM/Firecracker)
	@if [ "$${HUSKER_RUN_IDLE_POLICY_E2E:-0}" = "1" ]; then \
		HUSKER_RUN_IGNORED_E2E=1 cargo nextest run -p husker-core --test idle_policy_e2e --run-ignored all; \
	else \
		echo "Skipping idle-policy e2e (set HUSKER_RUN_IDLE_POLICY_E2E=1; needs Linux/KVM/Firecracker + HUSKER_E2E_KERNEL/ROOTFS)"; \
		[ -n "$${GITHUB_ACTIONS:-}" ] && echo "::warning title=idle-policy e2e gate not run::idle-policy e2e was SKIPPED (HUSKER_RUN_IDLE_POLICY_E2E is not '1'); this job is green but exercised no e2e"; \
		true; \
	fi

# Gated OCI-import boot e2e: import a Docker image and boot it as an
# agent-supervised microVM (the OCI-native sandbox keystone). Needs Linux with
# KVM + Firecracker + the x86_64-musl target, and TAP/Firecracker privileges
# (run under sudo). Fetches a built-in-driver kernel unless HUSKER_E2E_KERNEL is
# set. Intended for a self-hosted [self-hosted, husker] runner.
# Usage: HUSKER_RUN_OCI_BOOT_E2E=1 make test-oci-boot-e2e-gated
test-oci-boot-e2e-gated: ## Gated OCI-import boot e2e (Linux/KVM/Firecracker)
	@if [ "$${HUSKER_RUN_OCI_BOOT_E2E:-0}" = "1" ]; then \
		bash scripts/ci/oci_boot_e2e.sh; \
	else \
		echo "Skipping OCI boot e2e (set HUSKER_RUN_OCI_BOOT_E2E=1; needs Linux/KVM/Firecracker/root)"; \
	fi

test-suspend-fork-e2e-gated: ## Gated suspend+fork e2e (Linux/KVM/Firecracker)
	@if [ "$${HUSKER_RUN_SUSPEND_FORK_E2E:-0}" = "1" ]; then \
		bash scripts/ci/suspend_fork_e2e.sh; \
	else \
		echo "Skipping suspend+fork e2e (set HUSKER_RUN_SUSPEND_FORK_E2E=1; needs Linux/KVM/Firecracker/root)"; \
	fi

test-pool-e2e-gated: ## Gated hot-pool concurrent-checkout e2e (Linux/KVM/Firecracker)
	@if [ "$${HUSKER_RUN_POOL_E2E:-0}" = "1" ]; then \
		bash scripts/ci/pool_e2e.sh; \
	else \
		echo "Skipping pool e2e (set HUSKER_RUN_POOL_E2E=1; needs Linux/KVM/Firecracker/root)"; \
	fi

# API/CLI contract tests (OpenAPI + CLI output schema stability)
test-contracts:
	cargo test -p husker-api --test openapi_contract
	cargo test -p husker --no-default-features -- --nocapture

# Core failure-injection tests
test-failure-injection:
	cargo test -p husker-core --test failure_injection

# Lightweight performance baseline and regression gate
test-perf-baseline:
	cargo test -p husker-api --test perf_baseline -- --nocapture

# Coverage gate (line + branch) for workspace quality floor.
coverage-ci:
	cargo llvm-cov --workspace --all-features --ignore-filename-regex 'crates/husker/src/main.rs|crates/husker-agent/src/main.rs|crates/husker-vmm/src/apple_vz.rs' --fail-under-lines 77 --lcov --output-path target/llvm-cov.info

# Mutation-testing gate: runs real mutation testing on the protocol crate and
# fails if any non-excluded mutant survives (see .cargo/mutants.toml for the
# documented equivalent/flaky exclusions).
mutation-gate:
	cargo mutants --package husker-agent-proto -j 4

# Graceful shutdown drill (SIGTERM path)
graceful-shutdown-drill:
	scripts/ci/graceful_shutdown_drill.sh

# Chaos/restart drill (force-kill and restart path)
chaos-tests:
	scripts/ci/chaos_restart_drill.sh

# Nightly long-run quality suite
nightly-quality: test-perf-baseline test-failure-injection mutation-gate graceful-shutdown-drill chaos-tests test-e2e-gated test-net-e2e-gated

# Update guest rootfs image with latest agent binary and inittab.
# Requires: aarch64-linux-musl-gcc cross-compiler, e2fsprogs (brew install e2fsprogs)
ROOTFS_IMAGE ?= $(HOME)/.local/share/husker/images/alpine-aarch64.ext4
DEBUGFS ?= $(shell find /opt/homebrew/Cellar/e2fsprogs -name debugfs -type f 2>/dev/null | head -1)
AGENT_BIN = target/aarch64-unknown-linux-musl/agent/husker-agent
GUEST_INITTAB = guest/inittab

update-rootfs: build-agent-aarch64
	@test -f "$(ROOTFS_IMAGE)" || { echo "Error: rootfs not found at $(ROOTFS_IMAGE)"; exit 1; }
	@test -n "$(DEBUGFS)" || { echo "Error: debugfs not found. Install e2fsprogs: brew install e2fsprogs"; exit 1; }
	@echo "Injecting agent and inittab into $(ROOTFS_IMAGE) (single debugfs session)..."
	@printf 'rm /usr/local/bin/husker-agent\nwrite %s /usr/local/bin/husker-agent\nset_inode_field /usr/local/bin/husker-agent mode 0100755\nrm /etc/inittab\nwrite %s /etc/inittab\n' \
		"$(AGENT_BIN)" "$(GUEST_INITTAB)" | $(DEBUGFS) -w "$(ROOTFS_IMAGE)"
	@echo "Verifying injected files..."
	@$(DEBUGFS) -R "dump /etc/inittab /tmp/husker-inittab-verify" "$(ROOTFS_IMAGE)" 2>/dev/null && \
		cmp -s "$(GUEST_INITTAB)" /tmp/husker-inittab-verify && \
		rm -f /tmp/husker-inittab-verify || \
		{ echo "Error: /etc/inittab in image does not match $(GUEST_INITTAB) -- injection failed"; rm -f /tmp/husker-inittab-verify; exit 1; }
	@$(DEBUGFS) -R "dump /usr/local/bin/husker-agent /tmp/husker-agent-verify" "$(ROOTFS_IMAGE)" 2>/dev/null && \
		cmp -s "$(AGENT_BIN)" /tmp/husker-agent-verify && \
		rm -f /tmp/husker-agent-verify || \
		{ echo "Error: /usr/local/bin/husker-agent in image does not match $(AGENT_BIN) -- injection failed"; rm -f /tmp/husker-agent-verify; exit 1; }
	@echo "Rootfs updated and verified."

# Build initramfs for Alpine-based husker VMs.
# ARCH defaults to aarch64; pass ARCH=x86_64 for Firecracker.
build-initramfs:
	guest/build-initramfs.sh $(ALPINE_VERSION) $(ARCH)

# Build an uncompressed kernel Image extracted from Alpine's linux-virt apk.
# ARCH defaults to aarch64 (for macOS VZ); pass x86_64 for Firecracker.
build-kernel-image:
	guest/build-kernel-image.sh $(ARCH)

# Build baseline Alpine rootfs with husker-agent and inittab baked in.
# ARCH=aarch64 builds for macOS VZ; ARCH=x86_64 for Firecracker.
build-rootfs:
ifeq ($(ARCH),x86_64)
	$(MAKE) build-agent
else
	$(MAKE) build-agent-aarch64
endif
	guest/build-rootfs.sh $(ARCH)

# Validate initramfs/inittab consistency (module presence, load order, DHCP config)
test-initramfs:
	guest/test-initramfs.sh

# Build k3s-ready rootfs image (requires root, debootstrap)
K3S_ROOTFS ?= k3s-rootfs.ext4
build-k3s-rootfs: build-agent
	sudo guest/build-k3s-rootfs.sh $(K3S_ROOTFS)

# Build k3s-compatible kernel (requires root, build-essential, flex, bison, libelf-dev)
K3S_KERNEL ?= /mnt/husker/vmlinux-k3s
build-k3s-kernel:
	sudo guest/build-k3s-kernel.sh $(K3S_KERNEL)

# Build the modules-free microVM kernel from source (CONFIG_MODULES=n, all drivers built in).
# Deps (Debian/Ubuntu): build-essential bc bison flex libelf-dev libssl-dev
# Output: ~/.local/share/husker/kernels/vmlinux (x86_64) or Image-virt (aarch64).
# Override output dir: HUSKER_KERNEL_OUT=/path bash guest/build-microvm-kernel.sh
build-microvm-kernel: ## Build the modules-free microVM kernel from source
	bash guest/build-microvm-kernel.sh

# Run k3s E2E cluster test (requires running daemon, k3s rootfs + kernel)
K3S_ROOTFS ?= k3s-rootfs.ext4
test-k3s:
	guest/test-k3s-cluster.sh $(K3S_ROOTFS)

# Run the daemon (development)
run-daemon:
	cargo run --package husker -- daemon --listen 127.0.0.1:7777

# Security audit
audit:
	cargo audit

# Dependency policy checks (advisories, bans, source provenance)
deny:
	cargo deny check advisories bans sources

# Update dependencies (requires: cargo install upd)
# Applies patch + minor Rust crate bumps only. Major bumps and non-Rust
# ecosystems (GitHub Actions, etc.) are surfaced by check-deps and handled
# manually: the workflow's GITHUB_TOKEN cannot push .github/workflows
# changes, and major bumps would break the automated PR's build.
update-deps:
	upd --apply --max-bump minor --lang rust

# Check for outdated dependencies
check-deps:
	upd --check

# Install development dependencies
setup:
	cargo install cargo-nextest cargo-audit cargo-deny upd

# ---------------------------------------------------------------------------
# Release
# ---------------------------------------------------------------------------
#
# vership bumps the version, writes the changelog, tags and pushes; the release
# workflow then builds and uploads the artifacts. post-release waits for those
# artifacts to actually exist before doing anything that consumes them, because
# the tag is published several minutes before the assets finish uploading.

release-patch:
	vership bump patch
	$(MAKE) post-release

release-minor:
	vership bump minor
	$(MAKE) post-release

release-major:
	vership bump major
	$(MAKE) post-release

# Wait for the published artifacts, update the local install, then run the
# optional rollout hook. Safe to re-run: every step is idempotent.
post-release:
	@v=$$(git describe --tags --abbrev=0); \
	url="https://github.com/rvben/husker/releases/download/$$v/husker-$$v-x86_64-unknown-linux-gnu.tar.gz"; \
	echo "==> waiting for the $$v release artifacts"; \
	tarry http "$$url" --timeout 20m
	vership update-local
# vership updates registry-managed copies. husker is installed from a path
# (cargo install --path, to embed the guest agent), so there is no registry
# copy and vership correctly reports changed:false with an empty install list.
# Reading that no-op as "local install updated" leaves a stale binary behind,
# so check the installed version against the tag and build from source when it
# does not match. An absent binary is reported as absent, not as a version.
	@want=$$(git describe --tags --abbrev=0 | sed 's/^v//'); \
	have=$$(husker --version 2>/dev/null | awk '{print $$2}'); \
	if [ "$$have" != "$$want" ]; then \
		echo "==> local install is $${have:-absent}, expected $$want; building from source"; \
		$(MAKE) install; \
	else \
		echo "==> local install already at $$want"; \
	fi
	@if [ -n "$(POST_RELEASE)" ]; then \
		echo "==> post-release: $(POST_RELEASE)"; \
		$(POST_RELEASE); \
	fi
