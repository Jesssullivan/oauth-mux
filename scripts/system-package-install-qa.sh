#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: system-package-install-qa.sh <version>

Downloads published oauth-mux deb/rpm release assets, verifies them against the
published SHA256SUMS file, installs them in clean Linux containers, and runs the
installed /usr/bin/oauth-mux binary.

Environment:
  OMUX_RELEASE_REPO     GitHub release repo (default: Jesssullivan/oauth-mux)
  OMUX_DEB_QA_IMAGE     Debian image (default: debian:bookworm-slim)
  OMUX_RPM_QA_IMAGE     RPM image (default: rockylinux:9)
  OMUX_EXPECT_CODEX_SHIM Require /usr/bin/codex package shim (default: 0)
  DOCKER                Docker-compatible runtime (default: docker)
EOF
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

version="${1:-}"
if [ -z "$version" ]; then
  usage
  exit 2
fi

repo="${OMUX_RELEASE_REPO:-Jesssullivan/oauth-mux}"
docker_bin="${DOCKER:-docker}"
deb_image="${OMUX_DEB_QA_IMAGE:-debian:bookworm-slim}"
rpm_image="${OMUX_RPM_QA_IMAGE:-rockylinux:9}"
expect_codex_shim="${OMUX_EXPECT_CODEX_SHIM:-0}"
base_url="https://github.com/${repo}/releases/download/v${version}"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'missing required command: %s\n' "$1" >&2
    exit 1
  fi
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    printf 'missing required command: sha256sum or shasum\n' >&2
    exit 1
  fi
}

download() {
  local name="$1"
  curl -fsSL -o "$workdir/$name" "$base_url/$name"
}

verify_release_checksum() {
  local name="$1"
  local expected actual
  expected="$(awk -v name="$name" '$2 == name {print $1}' "$workdir/SHA256SUMS")"
  if [ -z "$expected" ]; then
    printf 'missing checksum entry for %s in SHA256SUMS\n' "$name" >&2
    exit 1
  fi
  actual="$(sha256_file "$workdir/$name")"
  if [ "$actual" != "$expected" ]; then
    printf 'checksum mismatch for %s\nexpected: %s\nactual:   %s\n' "$name" "$expected" "$actual" >&2
    exit 1
  fi
  printf '%s: OK\n' "$name"
}

require_command curl
require_command awk
require_command "$docker_bin"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

deb_name="oauth-mux_${version}_amd64.deb"
rpm_name="oauth-mux-${version}-1.x86_64.rpm"

printf 'downloading oauth-mux %s package assets from %s\n' "$version" "$base_url"
download SHA256SUMS
download "$deb_name"
download "$rpm_name"

verify_release_checksum "$deb_name"
verify_release_checksum "$rpm_name"

deb_check="set -e; dpkg -i /qa/$deb_name >/dev/null; dpkg-query -W oauth-mux; /usr/bin/oauth-mux version | grep 'oauth-mux $version'"
rpm_check="set -e; rpm -i /qa/$rpm_name; rpm -q oauth-mux; rpm -ql oauth-mux | grep '^/usr/bin/oauth-mux$'; /usr/bin/oauth-mux version | grep 'oauth-mux $version'"
if [ "$expect_codex_shim" = "1" ]; then
  deb_check="set -e; dpkg -i /qa/$deb_name >/dev/null; dpkg-query -W oauth-mux; test -x /usr/bin/codex; grep OMUX_CODEX_SHIM /usr/bin/codex; /usr/bin/oauth-mux version | grep 'oauth-mux $version'"
  rpm_check="set -e; rpm -i /qa/$rpm_name; rpm -q oauth-mux; rpm -ql oauth-mux | grep '^/usr/bin/oauth-mux$'; rpm -ql oauth-mux | grep '^/usr/bin/codex$'; grep OMUX_CODEX_SHIM /usr/bin/codex; /usr/bin/oauth-mux version | grep 'oauth-mux $version'"
fi

printf 'installing %s in %s\n' "$deb_name" "$deb_image"
"$docker_bin" run --rm \
  -v "$workdir:/qa:ro" \
  "$deb_image" \
  sh -lc "$deb_check"

printf 'installing %s in %s\n' "$rpm_name" "$rpm_image"
"$docker_bin" run --rm \
  -v "$workdir:/qa:ro" \
  "$rpm_image" \
  sh -lc "$rpm_check"

printf 'system package install QA passed for oauth-mux %s\n' "$version"
