#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

version="${1:-${VERSION:-0.1.0}}"
version="${version#v}"

out_dir="$repo_root/dist/out/v${version}"
artifacts_dir="$out_dir/artifacts"
npm_tgz_dir="$out_dir/npm-tarballs"
homebrew_formula="$out_dir/homebrew/oauth-mux.rb"

required_artifacts=(
  "oauth-mux-x86_64-linux.tar.gz"
  "oauth-mux-aarch64-linux.tar.gz"
  "oauth-mux-x86_64-macos.tar.gz"
  "oauth-mux-aarch64-macos.tar.gz"
  "oauth-mux-x86_64-windows.tar.gz"
  "oauth-mux-aarch64-windows.tar.gz"
  "oauth-mux_0.1.0_amd64.deb"
  "oauth-mux_0.1.0_arm64.deb"
  "oauth-mux-0.1.0-1.x86_64.rpm"
  "oauth-mux-0.1.0-1.aarch64.rpm"
  "install.sh"
)

required_npm_tarballs=(
  "oauth-mux-0.1.0.tgz"
  "oauth-mux-darwin-arm64-0.1.0.tgz"
  "oauth-mux-darwin-x64-0.1.0.tgz"
  "oauth-mux-linux-arm64-0.1.0.tgz"
  "oauth-mux-linux-x64-0.1.0.tgz"
  "oauth-mux-win32-arm64-0.1.0.tgz"
  "oauth-mux-win32-x64-0.1.0.tgz"
)

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  else
    shasum -a 256 "$1" | awk '{ print $1 }'
  fi
}

require_file() {
  if [ ! -f "$1" ]; then
    printf 'missing required release file: %s\n' "$1" >&2
    exit 1
  fi
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'missing required command for release smoke: %s\n' "$1" >&2
    exit 1
  fi
}

printf 'checking release tree: %s\n' "$out_dir"
if [ ! -d "$out_dir" ]; then
  printf 'release output does not exist: %s\n' "$out_dir" >&2
  exit 1
fi

for artifact in "${required_artifacts[@]}"; do
  artifact="${artifact/0.1.0/${version}}"
  require_file "$artifacts_dir/$artifact"
done

require_file "$artifacts_dir/SHA256SUMS"
require_file "$homebrew_formula"

printf 'checking checksums...\n'
while read -r expected filename; do
  [ -n "${expected:-}" ] || continue
  require_file "$artifacts_dir/$filename"
  actual="$(hash_file "$artifacts_dir/$filename")"
  if [ "$actual" != "$expected" ]; then
    printf 'checksum mismatch for %s: expected %s got %s\n' "$filename" "$expected" "$actual" >&2
    exit 1
  fi
done <"$artifacts_dir/SHA256SUMS"

printf 'checking archive contents...\n'
for archive in \
  oauth-mux-x86_64-linux.tar.gz \
  oauth-mux-aarch64-linux.tar.gz \
  oauth-mux-x86_64-macos.tar.gz \
  oauth-mux-aarch64-macos.tar.gz; do
  tar -tzf "$artifacts_dir/$archive" | grep -qx 'oauth-mux'
done
for archive in \
  oauth-mux-x86_64-windows.tar.gz \
  oauth-mux-aarch64-windows.tar.gz; do
  tar -tzf "$artifacts_dir/$archive" | grep -qx 'oauth-mux.exe'
done

printf 'checking Homebrew formula...\n'
if grep -q '\${' "$homebrew_formula"; then
  printf 'unrendered placeholder remains in %s\n' "$homebrew_formula" >&2
  exit 1
fi
if command -v ruby >/dev/null 2>&1; then
  ruby -c "$homebrew_formula" >/dev/null
fi

printf 'checking npm tarballs...\n'
require_command npm
for tarball in "${required_npm_tarballs[@]}"; do
  tarball="${tarball/0.1.0/${version}}"
  require_file "$npm_tgz_dir/$tarball"
done

os="$(uname -s)"
arch="$(uname -m)"
case "$os:$arch" in
  Darwin:arm64|Darwin:aarch64) platform_tgz="oauth-mux-darwin-arm64-${version}.tgz" ;;
  Darwin:x86_64|Darwin:amd64) platform_tgz="oauth-mux-darwin-x64-${version}.tgz" ;;
  Linux:arm64|Linux:aarch64) platform_tgz="oauth-mux-linux-arm64-${version}.tgz" ;;
  Linux:x86_64|Linux:amd64) platform_tgz="oauth-mux-linux-x64-${version}.tgz" ;;
  *)
    printf 'skipping local npm install smoke for unsupported host platform: %s/%s\n' "$os" "$arch"
    platform_tgz=""
    ;;
esac

if [ -n "${platform_tgz:-}" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  export npm_config_cache="$tmp/npm-cache"
  export npm_config_update_notifier=false
  npm install \
    --prefix "$tmp/app" \
    "$npm_tgz_dir/$platform_tgz" \
    "$npm_tgz_dir/oauth-mux-${version}.tgz" \
    --ignore-scripts=false \
    --no-audit \
    --no-fund >/dev/null
  "$tmp/app/node_modules/.bin/oauth-mux" version | grep -qx "oauth-mux ${version}"

  printf 'checking curl installer...\n'
  install_dir="$tmp/install-bin"
  VERSION="$version" \
    OMUX_RELEASE_BASE_URL="file://$artifacts_dir" \
    INSTALL_DIR="$install_dir" \
    sh "$artifacts_dir/install.sh" >/dev/null
  "$install_dir/oauth-mux" version | grep -qx "oauth-mux ${version}"
fi

printf 'release smoke passed for v%s\n' "$version"
