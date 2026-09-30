#!/bin/sh
# Executed only inside a disposable Ubuntu builder VM by `husker dev prepare`.
set -eu
export DEBIAN_FRONTEND=noninteractive
export HOME=/root
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl git build-essential \
    pkg-config libssl-dev python3 python3-venv python3-pip docker.io docker-compose-v2 \
    sudo iproute2 procps xz-utils openssh-client

# Resolve Node's current 22.x distribution and verify its published SHA-256.
case "$(uname -m)" in x86_64) node_arch=x64 ;; aarch64) node_arch=arm64 ;; *) exit 1 ;; esac
node_dir=$(mktemp -d)
trap 'rm -rf "$node_dir"' EXIT
curl -fsSL https://nodejs.org/dist/latest-v22.x/SHASUMS256.txt -o "$node_dir/SHASUMS256.txt"
node_archive=$(awk -v suffix="linux-$node_arch.tar.xz" '$2 ~ suffix "$" {print $2; exit}' "$node_dir/SHASUMS256.txt")
test -n "$node_archive"
curl -fsSL "https://nodejs.org/dist/latest-v22.x/$node_archive" -o "$node_dir/$node_archive"
(cd "$node_dir"; awk -v file="$node_archive" '$2 == file' SHASUMS256.txt | sha256sum -c -)
tar -xJf "$node_dir/$node_archive" --strip-components=1 -C /usr/local

# Install into a shared tool directory; agent sessions run as developer.
export RUSTUP_HOME=/opt/rustup
export CARGO_HOME=/opt/cargo
curl -fsSL https://sh.rustup.rs -o "$node_dir/rustup.sh"
sh "$node_dir/rustup.sh" -y --no-modify-path --profile minimal \
    --default-toolchain "${HUSKER_DEV_RUST_TOOLCHAIN:?}"
ln -sf /opt/cargo/bin/rustc /usr/local/bin/rustc
ln -sf /opt/cargo/bin/cargo /usr/local/bin/cargo
ln -sf /opt/cargo/bin/rustup /usr/local/bin/rustup
npm install -g "@openai/codex@${HUSKER_DEV_CODEX_VERSION:?}" \
    "@anthropic-ai/claude-code@${HUSKER_DEV_CLAUDE_VERSION:?}"
id developer >/dev/null 2>&1 || useradd --create-home --shell /bin/bash developer
chown -R developer:developer /opt/cargo /opt/rustup
printf '%s\n' 'developer ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/husker-developer
chmod 0440 /etc/sudoers.d/husker-developer
usermod -aG docker developer
mkdir -p /workspace /etc/husker
chown developer:developer /workspace
# These variables must expand when a user sources the profile, not during provisioning.
# shellcheck disable=SC2016
printf '%s\n' 'export RUSTUP_HOME=/opt/rustup' 'export CARGO_HOME=/opt/cargo' \
    'export PATH=/opt/cargo/bin:/usr/local/bin:$PATH' > /etc/profile.d/husker-dev.sh
runuser -u developer -- git -C /workspace init

# Persist resolved versions, never credentials. Prepared image names are immutable.
{
    printf 'node=%s\n' "$(node --version)"
    printf 'python=%s\n' "$(python3 --version)"
    printf 'rust=%s\n' "$(rustc --version)"
    printf 'docker=%s\n' "$(dockerd --version)"
    printf 'codex=%s\n' "$(codex --version)"
    printf 'claude=%s\n' "$(runuser -u developer -- claude --version)"
    dpkg-query -W -f='${Package}=${Version}\n'
} > /etc/husker/dev-manifest.txt
apt-get clean
rm -rf /var/lib/apt/lists/* "$node_dir"
trap - EXIT
