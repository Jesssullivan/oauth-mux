#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

version="${1:-${VERSION:-$("$repo_root/scripts/project-version.sh")}}"
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
  "oauth-mux_${version}_amd64.deb"
  "oauth-mux_${version}_arm64.deb"
  "oauth-mux-${version}-1.x86_64.rpm"
  "oauth-mux-${version}-1.aarch64.rpm"
  "install.sh"
)

required_npm_tarballs=(
  "oauth-mux-${version}.tgz"
  "oauth-mux-darwin-arm64-${version}.tgz"
  "oauth-mux-darwin-x64-${version}.tgz"
  "oauth-mux-linux-arm64-${version}.tgz"
  "oauth-mux-linux-x64-${version}.tgz"
  "oauth-mux-windows-arm64-${version}.tgz"
  "oauth-mux-windows-x64-${version}.tgz"
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

archive_contains() {
  local archive="$1"
  local expected="$2"
  tar -tzf "$archive" | awk -v expected="$expected" '$0 == expected { found = 1 } END { exit found ? 0 : 1 }'
}

printf 'checking release tree: %s\n' "$out_dir"
if [ ! -d "$out_dir" ]; then
  printf 'release output does not exist: %s\n' "$out_dir" >&2
  exit 1
fi

for artifact in "${required_artifacts[@]}"; do
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
  archive_contains "$artifacts_dir/$archive" 'oauth-mux'
  archive_contains "$artifacts_dir/$archive" 'codex'
done
for archive in \
  oauth-mux-x86_64-windows.tar.gz \
  oauth-mux-aarch64-windows.tar.gz; do
  archive_contains "$artifacts_dir/$archive" 'oauth-mux.exe'
done

printf 'checking Homebrew formula...\n'
if grep -q -E '\$\{(VERSION|SHA_[A-Z0-9_]+)\}' "$homebrew_formula"; then
  printf 'unrendered placeholder remains in %s\n' "$homebrew_formula" >&2
  exit 1
fi
version_line="$(awk '/^[[:space:]]+version / { print NR; exit }' "$homebrew_formula")"
license_line="$(awk '/^[[:space:]]+license / { print NR; exit }' "$homebrew_formula")"
if [ -z "${version_line:-}" ] || [ -z "${license_line:-}" ] || [ "$version_line" -ge "$license_line" ]; then
  printf 'Homebrew formula must put version before license for brew audit compatibility: %s\n' "$homebrew_formula" >&2
  exit 1
fi
"$repo_root/scripts/homebrew-version-check.sh" "$version" "$homebrew_formula"
if command -v ruby >/dev/null 2>&1; then
  ruby -c "$homebrew_formula" >/dev/null
fi

printf 'checking npm tarballs...\n'
require_command npm
for tarball in "${required_npm_tarballs[@]}"; do
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
  native_codex="$tmp/native-codex"
  cat >"$native_codex" <<'EOF'
#!/bin/sh
case "$1" in
  --version) echo "native-codex-stub 0.0.0" ;;
  *) echo "native-codex-stub" ;;
esac
EOF
  chmod 0755 "$native_codex"
  OMUX_CODEX_BIN="$native_codex" "$tmp/app/node_modules/.bin/codex" --version | grep -qx "native-codex-stub 0.0.0"

  printf 'checking curl installer...\n'
  install_dir="$tmp/install-bin"
  VERSION="$version" \
    OMUX_RELEASE_BASE_URL="file://$artifacts_dir" \
    INSTALL_DIR="$install_dir" \
    sh "$artifacts_dir/install.sh" >/dev/null
  "$install_dir/oauth-mux" version | grep -qx "oauth-mux ${version}"
  test -x "$install_dir/codex"
  grep -q OMUX_CODEX_SHIM "$install_dir/codex"
  OMUX_CODEX_BIN="$native_codex" "$install_dir/codex" --version | grep -qx "native-codex-stub 0.0.0"
fi

printf 'release smoke passed for v%s\n' "$version"
