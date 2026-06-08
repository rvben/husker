#!/bin/bash
# Build a baseline Alpine ext4 rootfs with husker-agent and inittab baked in.
#
# Usage:
#   ./guest/build-rootfs.sh [ARCH] [ALPINE_VERSION]
#
# Requires: debugfs (e2fsprogs), agent binary already built for $ARCH at
#   target/${ARCH}-unknown-linux-musl/agent/husker-agent
#
# Output: ~/.local/share/husker/images/alpine-${ARCH}.ext4 (256 MiB)

set -euo pipefail

ARCH="${1:-aarch64}"
ALPINE_VERSION="${2:-3.21}"
OUTPUT_DIR="${HUSKER_IMAGE_OUT:-${HOME}/.local/share/husker/images}"
WORK_DIR="$(mktemp -d)"
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

# Resolve paths relative to the repo root, not CWD.
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

case "$ARCH" in
    aarch64|x86_64) ;;
    *) echo "ERROR: unsupported arch $ARCH" >&2; exit 1 ;;
esac

DEBUGFS="${DEBUGFS:-$(command -v debugfs 2>/dev/null || find /opt/homebrew/Cellar/e2fsprogs -name debugfs -type f 2>/dev/null | head -1)}"
MKFS_EXT4="${MKFS_EXT4:-$(command -v mkfs.ext4 2>/dev/null || find /opt/homebrew/Cellar/e2fsprogs -name mkfs.ext4 -type f 2>/dev/null | head -1)}"
[ -x "$DEBUGFS" ]   || { echo "ERROR: debugfs not found (brew install e2fsprogs)" >&2; exit 1; }
[ -x "$MKFS_EXT4" ] || { echo "ERROR: mkfs.ext4 not found (brew install e2fsprogs)" >&2; exit 1; }

AGENT_BIN="$SCRIPT_DIR/target/${ARCH}-unknown-linux-musl/agent/husker-agent"
[ -f "$AGENT_BIN" ] || { echo "ERROR: agent binary missing at $AGENT_BIN (run make build-agent-aarch64 / build-agent)" >&2; exit 1; }

# ── Fetch Alpine minirootfs tarball ──────────────────────────────────
MINI_URL="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION}/releases/${ARCH}/"
MINI_NAME=$(curl -sL "$MINI_URL" | grep -o "alpine-minirootfs-[0-9][^\"]*-${ARCH}\.tar\.gz" | head -1)
[ -z "$MINI_NAME" ] && { echo "ERROR: minirootfs tarball not found" >&2; exit 1; }
echo "Downloading $MINI_NAME"
curl -sL "${MINI_URL}${MINI_NAME}" -o "$WORK_DIR/minirootfs.tar.gz"

# ── Populate an ext4 image via debugfs -f (no loop mount needed) ─────
IMG="$WORK_DIR/rootfs.ext4"
truncate -s 256M "$IMG"
"$MKFS_EXT4" -q -F -L husker-root "$IMG"

# Extract and layer the minirootfs, agent, and inittab before injecting.
TAR_DIR="$WORK_DIR/extract"
mkdir -p "$TAR_DIR"
tar xzf "$WORK_DIR/minirootfs.tar.gz" -C "$TAR_DIR"

mkdir -p "$TAR_DIR/usr/local/bin"
cp "$AGENT_BIN" "$TAR_DIR/usr/local/bin/husker-agent"
chmod 0755 "$TAR_DIR/usr/local/bin/husker-agent"
mkdir -p "$TAR_DIR/usr/local/sbin"
cp "$SCRIPT_DIR/guest/husker-net.sh" "$TAR_DIR/usr/local/sbin/husker-net.sh"
chmod 0755 "$TAR_DIR/usr/local/sbin/husker-net.sh"
mkdir -p "$TAR_DIR/etc"
cp "$SCRIPT_DIR/guest/inittab" "$TAR_DIR/etc/inittab"
chmod 0644 "$TAR_DIR/etc/inittab"

# Walk the tree sorted to guarantee parent directories are created before
# their children. Symlinks and regular files are recorded as debugfs commands;
# block/char device nodes are skipped because devtmpfs recreates them at boot.
DBG_CMDS="$WORK_DIR/debugfs.cmd"
: > "$DBG_CMDS"

# Emit the permission bits as a 4-digit octal (suid/sgid/sticky + rwx*3).
# BSD `stat -f '%p'` pads; GNU `stat -c '%a'` does not, so normalise ourselves —
# otherwise debugfs parses `04755` as 0o04755 (zero file-type nibble) and the
# resulting inode is not a directory, breaking every subsequent symlink.
perm_suffix() {
    local m
    if m=$(stat -f '%p' "$1" 2>/dev/null); then
        echo "${m: -4}"
    else
        m=$(stat -c '%a' "$1")
        printf '%04o\n' "$((8#$m))"
    fi
}

( cd "$TAR_DIR" && find . -mindepth 1 -print0 | sort -z | while IFS= read -r -d '' entry; do
    dest="/${entry#./}"
    if [ -L "$entry" ]; then
        target=$(readlink "$entry")
        echo "symlink $dest $target"
    elif [ -d "$entry" ]; then
        echo "mkdir $dest"
        echo "set_inode_field $dest mode 04$(perm_suffix "$entry")"
    elif [ -f "$entry" ]; then
        echo "write $entry $dest"
        echo "set_inode_field $dest mode 010$(perm_suffix "$entry")"
    else
        echo "# skipping special file: $dest" >&2
    fi
done ) >> "$DBG_CMDS"

# Run debugfs from inside the extracted tree so relative source paths in
# "write ./foo/bar /foo/bar" commands resolve correctly.
(cd "$TAR_DIR" && "$DEBUGFS" -w -f "$DBG_CMDS" "$IMG" >/dev/null)

# debugfs exits 0 even when individual commands in the command file fail.
# Probe the populated image for key files before declaring success.
if ! "$DEBUGFS" -R "stat /usr/local/bin/husker-agent" "$IMG" 2>/dev/null | grep -q "Type: regular"; then
    echo "ERROR: husker-agent was not written to the image (debugfs populate may have failed)" >&2
    exit 1
fi
if ! "$DEBUGFS" -R "stat /usr/local/sbin/husker-net.sh" "$IMG" 2>/dev/null | grep -q "Type: regular"; then
    echo "ERROR: husker-net.sh was not written to the image (debugfs populate may have failed)" >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
OUT_PATH="$OUTPUT_DIR/alpine-${ARCH}.ext4"
mv "$IMG" "$OUT_PATH"

echo "Built: $OUT_PATH ($(du -h "$OUT_PATH" | cut -f1))"
echo "Verify: $DEBUGFS -R 'ls /usr/local/bin' $OUT_PATH"
