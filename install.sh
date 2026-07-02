#!/bin/sh
# husker installer
#
# Usage:
#   curl -sSfL https://raw.githubusercontent.com/rvben/husker/main/install.sh | sh
#   curl -sSfL https://raw.githubusercontent.com/rvben/husker/main/install.sh | sh -s -- --prefix /usr/local
#
# Options:
#   --prefix <dir>   Install prefix. Default: $HOME/.local
#   --version <tag>  Pin a release tag (e.g. v0.1.2). Default: latest release.
#
# Env equivalents: HUSKER_PREFIX, HUSKER_VERSION

set -eu

REPO="rvben/husker"
PREFIX="${HUSKER_PREFIX:-$HOME/.local}"
VERSION="${HUSKER_VERSION:-}"

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2 ;;
    --prefix=*) PREFIX="${1#--prefix=}"; shift ;;
    --version) VERSION="$2"; shift 2 ;;
    --version=*) VERSION="${1#--version=}"; shift ;;
    -h|--help)
      cat <<'USAGE'
husker installer

Usage:
  curl -sSfL https://raw.githubusercontent.com/rvben/husker/main/install.sh | sh
  curl -sSfL https://raw.githubusercontent.com/rvben/husker/main/install.sh | sh -s -- --prefix /usr/local

Options:
  --prefix <dir>   Install prefix. Default: $HOME/.local
  --version <tag>  Pin a release tag (e.g. v0.1.2). Default: latest release.

Env equivalents: HUSKER_PREFIX, HUSKER_VERSION
USAGE
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

os="$(uname -s)"
case "$os" in
  Linux)  target_os="unknown-linux-gnu" ;;
  Darwin) target_os="apple-darwin" ;;
  MINGW*|MSYS*|CYGWIN*|Windows_NT)
    echo "error: husker does not run on native Windows." >&2
    echo "It is a Linux/macOS microVM manager (needs KVM or Apple Virtualization)." >&2
    echo "On Windows, install inside WSL2 with nested virtualization enabled:" >&2
    echo "  wsl --install, then run this script from your WSL2 Linux shell." >&2
    exit 1
    ;;
  *) echo "error: unsupported OS: $os" >&2; exit 1 ;;
esac

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) target_arch="x86_64" ;;
  aarch64|arm64) target_arch="aarch64" ;;
  *) echo "error: unsupported architecture: $arch" >&2; exit 1 ;;
esac

target="${target_arch}-${target_os}"

command -v tar >/dev/null 2>&1 || { echo "error: tar not found" >&2; exit 1; }

if command -v curl >/dev/null 2>&1; then
  fetch_file() { curl -fsSL "$1" -o "$2"; }
  fetch_stdout() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch_file() { wget -qO "$2" "$1"; }
  fetch_stdout() { wget -qO- "$1"; }
else
  echo "error: requires curl or wget" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha256_of() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  sha256_of() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  echo "error: requires sha256sum or shasum" >&2
  exit 1
fi

if [ -z "$VERSION" ]; then
  echo "Resolving latest release..."
  VERSION="$(fetch_stdout "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep -E '"tag_name":' \
    | head -1 \
    | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
  if [ -z "$VERSION" ]; then
    echo "error: could not resolve latest release tag" >&2
    exit 1
  fi
fi
case "$VERSION" in
  v*) ;;
  *) VERSION="v$VERSION" ;;
esac

archive="husker-${VERSION}-${target}.tar.gz"
url="https://github.com/${REPO}/releases/download/${VERSION}/${archive}"
sha_url="${url}.sha256"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Downloading ${archive}..."
fetch_file "$url" "${tmp}/${archive}"
fetch_file "$sha_url" "${tmp}/${archive}.sha256"

expected="$(awk '{print $1}' "${tmp}/${archive}.sha256")"
actual="$(sha256_of "${tmp}/${archive}")"
if [ "$expected" != "$actual" ]; then
  echo "error: checksum mismatch" >&2
  echo "  expected: $expected" >&2
  echo "  actual:   $actual" >&2
  exit 1
fi
echo "Checksum OK."

mkdir -p "${tmp}/extract" "${PREFIX}/bin"
tar -xzf "${tmp}/${archive}" -C "${tmp}/extract"
mv "${tmp}/extract/husker" "${PREFIX}/bin/husker"
chmod +x "${PREFIX}/bin/husker"

echo
echo "Installed husker ${VERSION} to ${PREFIX}/bin/husker"

case ":$PATH:" in
  *":${PREFIX}/bin:"*)
    ;;
  *)
    echo
    echo "Note: ${PREFIX}/bin is not in your PATH. Add this to your shell config:"
    echo "    export PATH=\"${PREFIX}/bin:\$PATH\""
    ;;
esac

echo
echo "Next steps:"
echo "  husker images pull        # fetch the default kernel + rootfs"
echo "  husker daemon &           # start the daemon"
echo "  husker run --name hello   # boot a VM"
