.PHONY: all build build-release build-agent build-agent-aarch64 build-release-macos sign-macos test test-unit test-macos test-e2e test-e2e-gated test-net-e2e-gated test-qemu-e2e-gated test-contracts test-failure-injection test-perf-baseline coverage-ci mutation-gate graceful-shutdown-drill chaos-tests nightly-quality lint fmt fmt-check clippy check check-macos clean install install-restart run-daemon update-rootfs build-initramfs test-initramfs build-kernel-image build-rootfs build-k3s-rootfs build-k3s-kernel test-k3s audit deny update-deps check-deps setup

# Target architecture for guest build targets (aarch64 = macOS VZ, x86_64 = Firecracker).
ARCH ?= aarch64
# Alpine Linux version used by build-initramfs.
ALPINE_VERSION ?= 3.21

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

# Build guest agent for ARM64 (for macOS/VZ guests)
build-agent-aarch64:
	CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=$(AARCH64_MUSL_LINKER) \
	cargo build --package husker-agent --profile agent --target aarch64-unknown-linux-musl

# Build release for macOS (no linux-net, with entitlement signing)
build-release-macos:
	cargo build --workspace --release --no-default-features
	$(MAKE) sign-macos

# Sign macOS binary with virtualization entitlement
sign-macos:
	codesign --entitlements husker.entitlements --force --sign - target/release/husker

# Check compilation without linux-net (macOS path)
check-macos:
	cargo check --workspace --no-default-features

# Run tests on macOS (without linux-net feature)
# Excludes husker-api whose integration tests require linux-net
test-macos:
	cargo nextest run --workspace --no-default-features --exclude husker-api 2>/dev/null || cargo test --workspace --no-default-features --exclude husker-api

# Run all tests
test:
	cargo nextest run --workspace 2>/dev/null || cargo test --workspace

# Run unit tests only (fast)
test-unit:
	cargo nextest run --workspace --lib 2>/dev/null || cargo test --workspace --lib

# Lint
lint: fmt-check clippy

# Check formatting
fmt-check:
	cargo fmt --all -- --check

# Format code
fmt:
	cargo fmt --all

# Clippy
clippy:
	cargo clippy --workspace --all-targets -- -D warnings

# Type check without building
check:
	cargo check --workspace --all-targets

# Clean build artifacts
clean:
	cargo clean

# Install husker binary (auto-detects macOS to disable linux-net and sign)
install:
ifeq ($(shell uname -s),Darwin)
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
test-e2e-gated:
	@if [ "$${HUSKER_RUN_IGNORED_E2E:-0}" = "1" ]; then \
		cargo test --package husker --test e2e -- --ignored; \
	else \
		echo "Skipping husker ignored e2e tests (set HUSKER_RUN_IGNORED_E2E=1 to enable)"; \
	fi

# Run ignored husker-net e2e tests only when explicitly enabled.
test-net-e2e-gated:
	@if [ "$${HUSKER_RUN_NET_E2E:-0}" = "1" ]; then \
		cargo test --package husker-net --test e2e_bridge -- --ignored; \
	else \
		echo "Skipping husker-net ignored e2e tests (set HUSKER_RUN_NET_E2E=1 to enable)"; \
	fi

# Real QEMU boot + vsock e2e (needs Linux KVM + vhost-vsock + qemu + images)
test-qemu-e2e-gated: ## Real QEMU boot + vsock e2e (needs Linux KVM + vhost-vsock + qemu + images)
	HUSKER_RUN_IGNORED_E2E=1 cargo nextest run -p husker-vmm --run-ignored all qemu_boots_and_vsock

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

# Mutation-testing smoke gate (tooling + target discoverability).
mutation-gate:
	cargo mutants --list --package husker-agent-proto > /dev/null

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
	@echo "Injecting agent binary into $(ROOTFS_IMAGE)..."
	$(DEBUGFS) -w "$(ROOTFS_IMAGE)" \
		-R "rm /usr/local/bin/husker-agent" 2>/dev/null; true
	$(DEBUGFS) -w "$(ROOTFS_IMAGE)" \
		-R "write $(AGENT_BIN) /usr/local/bin/husker-agent"
	$(DEBUGFS) -w "$(ROOTFS_IMAGE)" \
		-R "set_inode_field /usr/local/bin/husker-agent mode 0100755"
	@echo "Injecting inittab into $(ROOTFS_IMAGE)..."
	$(DEBUGFS) -w "$(ROOTFS_IMAGE)" \
		-R "rm /etc/inittab" 2>/dev/null; true
	$(DEBUGFS) -w "$(ROOTFS_IMAGE)" \
		-R "write $(GUEST_INITTAB) /etc/inittab"
	@echo "Rootfs updated. Verify with:"
	@echo "  $(DEBUGFS) -R 'stat /usr/local/bin/husker-agent' $(ROOTFS_IMAGE)"
	@echo "  $(DEBUGFS) -R 'cat /etc/inittab' $(ROOTFS_IMAGE)"

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
