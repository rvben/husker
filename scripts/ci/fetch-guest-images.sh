#!/usr/bin/env bash
# Download the x86_64 guest kernel, rootfs and initramfs used by the self-hosted
# e2e jobs from a PINNED `images-*` release and verify their sha256 before any
# job uses them. Those jobs run as root, so an unverified download would be
# code execution as root on the runner.
#
# The pin is two things kept in this directory:
#   IMAGES_TAG below            the exact release (never "latest")
#   guest-images.sha256         sha256sum-format hashes of the three assets
#
# The hashes were computed from the downloaded assets and cross-checked against
# the release's own SHA256SUMS and the digests GitHub reports for the assets.
#
# To move to newer images: pick the tag, download the three assets, compare
# `sha256sum` with that release's SHA256SUMS, then update IMAGES_TAG and
# guest-images.sha256 in the same commit.
#
# Usage: fetch-guest-images.sh DEST_DIR [--checksums FILE] [--base-url URL]
#   --checksums FILE  hash file to verify against (default: guest-images.sha256)
#   --base-url URL    download base (default: the pinned release URL); tests use
#                     a file:// URL
# The assets land in DEST_DIR under their release names. On any failure DEST_DIR
# is removed and the exit status is non-zero.

set -euo pipefail

IMAGES_TAG="images-2026-11-18T200307Z"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
checksums="${here}/guest-images.sha256"
base_url="https://github.com/rvben/husker/releases/download/${IMAGES_TAG}"
dest=""

while [ $# -gt 0 ]; do
  case "$1" in
    --checksums) checksums="${2:?--checksums needs a file}"; shift 2 ;;
    --base-url) base_url="${2:?--base-url needs a URL}"; shift 2 ;;
    -h|--help) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "fetch-guest-images.sh: unknown argument '$1'" >&2; exit 2 ;;
    *) [ -z "${dest}" ] || { echo "fetch-guest-images.sh: one DEST_DIR only" >&2; exit 2; }
       dest="$1"; shift ;;
  esac
done
[ -n "${dest}" ] || { echo "fetch-guest-images.sh: DEST_DIR required" >&2; exit 2; }
[ -s "${checksums}" ] || { echo "fetch-guest-images.sh: checksum file ${checksums} missing or empty" >&2; exit 2; }

checksums="$(cd "$(dirname "${checksums}")" && pwd)/$(basename "${checksums}")"

# GNU coreutils on the runner; macOS only has shasum.
if command -v sha256sum >/dev/null 2>&1; then
  verify() { sha256sum --check --strict "$1"; }
else
  verify() { shasum -a 256 --check --strict "$1"; }
fi

rm -rf "${dest}"
mkdir -p "${dest}"
trap 'status=$?; [ "${status}" -eq 0 ] || rm -rf "${dest}"' EXIT

echo "using images from ${base_url##*/}"
# The file names come from the checksum file, so the set of downloads and the
# set of verified files cannot diverge.
while read -r _hash name; do
  curl -fsSL "${base_url}/${name}" -o "${dest}/${name}"
done < "${checksums}"

( cd "${dest}" && verify "${checksums}" )
