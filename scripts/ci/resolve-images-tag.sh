#!/usr/bin/env bash
# Resolve the newest `images-*` release tag - the channel carrying the default
# guest kernel, rootfs and initramfs.
#
# This is the single source of truth for CI. It mirrors
# `crates/husker/src/images.rs::select_images_tag`, which the shipped binary
# uses to resolve the same tag at runtime. The `shell_resolver_matches_rust`
# test in that file runs this script over the Rust fixtures and fails if the
# two ever disagree, so the duplication cannot drift apart silently.
#
# Usage:
#   resolve-images-tag.sh                 print the tag
#   resolve-images-tag.sh --url           print the release download base URL
#   resolve-images-tag.sh --repo O/N      repository (default: rvben/husker)
#   resolve-images-tag.sh --tags-file F   select from a newline-delimited tag
#                                         list instead of querying the API
#                                         ("-" reads stdin); used by the tests
#
# GITHUB_TOKEN, when set, authenticates the API call to dodge the 60/hr
# unauthenticated rate limit.

set -euo pipefail

REPO="rvben/husker"
TAGS_FILE=""
PRINT_URL=0

while [ $# -gt 0 ]; do
  case "$1" in
    --url) PRINT_URL=1; shift ;;
    --repo) REPO="${2:?--repo needs OWNER/NAME}"; shift 2 ;;
    --tags-file) TAGS_FILE="${2:?--tags-file needs a path or -}"; shift 2 ;;
    -h|--help) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "resolve-images-tag.sh: unknown argument '$1'" >&2; exit 2 ;;
  esac
done

# Pull `tag_name` values out of the releases JSON. Anchoring to the field keeps
# a tag quoted in some release's body from being mistaken for a real tag, which
# a bare grep over the raw JSON would do.
extract_tag_names() {
  grep -oE '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4 || true
}

# Filter to the images channel and take the lexicographic maximum.
#
# Newest == greatest holds only because the tag carries a fixed-width,
# big-endian UTC timestamp (`images-YYYY-MM-DD` or `images-YYYY-MM-DDThhmmssZ`).
# Any tag whose first differing character can sort above a later one - a version
# number, a run id, an unpadded field - would pin every consumer to the wrong
# release, silently and permanently. `build-images.yml` must preserve that
# property.
#
# LC_ALL=C makes the comparison bytewise, matching Rust's `Ord for String`. A
# locale-aware sort can order punctuation differently and would break parity.
select_images_tag() {
  LC_ALL=C grep '^images-' | LC_ALL=C sort | tail -n 1 || true
}

fetch_tag_names() {
  local auth=() page=1 body names
  [ -n "${GITHUB_TOKEN:-}" ] && auth=(-H "Authorization: Bearer ${GITHUB_TOKEN}")

  # Walk pages newest-first until one yields an images-* tag. Stopping at the
  # first page without pagination would silently return a STALE tag once 100
  # releases pile up after the newest image build - and a stale tag downloads
  # successfully, so nothing would ever flag it. The cap bounds the cost; the
  # loop normally exits on page 1.
  while [ "${page}" -le 10 ]; do
    body="$(curl -fsSL "${auth[@]}" -H 'Accept: application/vnd.github+json' \
      "https://api.github.com/repos/${REPO}/releases?per_page=100&page=${page}")"
    names="$(printf '%s' "${body}" | extract_tag_names)"
    # An empty page means the release list is exhausted.
    [ -n "${names}" ] || break
    printf '%s\n' "${names}"
    if printf '%s\n' "${names}" | LC_ALL=C grep -q '^images-'; then
      break
    fi
    page=$((page + 1))
  done
}

if [ -n "${TAGS_FILE}" ]; then
  if [ "${TAGS_FILE}" = "-" ]; then
    tags="$(cat)"
  else
    tags="$(cat "${TAGS_FILE}")"
  fi
else
  tags="$(fetch_tag_names)"
fi

tag="$(printf '%s\n' "${tags}" | select_images_tag)"

if [ -z "${tag}" ]; then
  echo "resolve-images-tag.sh: no 'images-*' release found for ${REPO}" >&2
  exit 1
fi

if [ "${PRINT_URL}" -eq 1 ]; then
  printf 'https://github.com/%s/releases/download/%s\n' "${REPO}" "${tag}"
else
  printf '%s\n' "${tag}"
fi
