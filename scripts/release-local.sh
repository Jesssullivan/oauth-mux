#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

version="${1:-${VERSION:-0.1.0}}"
version="${version#v}"

out_dir="$repo_root/dist/out/v${version}"
artifacts_dir="$out_dir/artifacts"
npm_dir="$out_dir/npm"
npm_tgz_dir="$out_dir/npm-tarballs"
homebrew_dir="$out_dir/homebrew"
nfpm_dir="$out_dir/nfpm"
work_dir="$out_dir/work"

rm -rf "$out_dir"
mkdir -p "$artifacts_dir" "$npm_dir" "$npm_tgz_dir" "$homebrew_dir" "$nfpm_dir" "$work_dir"

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  else
    shasum -a 256 "$1" | awk '{ print $1 }'
  fi
}

write_artifact_checksums() {
  : >"$artifacts_dir/SHA256SUMS"
  for artifact in "$artifacts_dir"/*; do
    [ -f "$artifact" ] || continue
    [ "$(basename "$artifact")" = "SHA256SUMS" ] && continue
    printf '%s  %s\n' "$(hash_file "$artifact")" "$(basename "$artifact")" >>"$artifacts_dir/SHA256SUMS"
  done
}

package_binary() {
  local build_dir="$1"
  local artifact="$2"
  local npm_pkg="$3"
  local npm_os="$4"
  local npm_cpu="$5"
  local binary_name="$6"
  local src="zig-out/${build_dir}/${binary_name}"

  if [ ! -f "$src" ]; then
    printf 'missing release binary: %s\n' "$src" >&2
    exit 1
  fi

  local stage="$work_dir/${artifact}"
  mkdir -p "$stage"
  cp "$src" "$stage/${binary_name}"
  chmod 0755 "$stage/${binary_name}"
  tar -czf "$artifacts_dir/${artifact}.tar.gz" -C "$stage" "$binary_name"

  local pkg_dir="$npm_dir/${npm_pkg}"
  mkdir -p "$pkg_dir/bin"
  cp "$src" "$pkg_dir/bin/${binary_name}"
  chmod 0755 "$pkg_dir/bin/${binary_name}"
  cat >"$pkg_dir/package.json" <<EOF
{
  "name": "${npm_pkg}",
  "version": "${version}",
  "description": "Platform binary for oauth-mux",
  "license": "MIT",
  "repository": "tinyland-inc/oauth-mux",
  "os": ["${npm_os}"],
  "cpu": ["${npm_cpu}"],
  "files": ["bin"]
}
EOF
}

printf 'building release binaries...\n'
zig build release

package_binary "x86_64-linux" "oauth-mux-x86_64-linux" "oauth-mux-linux-x64" "linux" "x64" "oauth-mux"
package_binary "aarch64-linux" "oauth-mux-aarch64-linux" "oauth-mux-linux-arm64" "linux" "arm64" "oauth-mux"
package_binary "x86_64-macos" "oauth-mux-x86_64-macos" "oauth-mux-darwin-x64" "darwin" "x64" "oauth-mux"
package_binary "aarch64-macos" "oauth-mux-aarch64-macos" "oauth-mux-darwin-arm64" "darwin" "arm64" "oauth-mux"
package_binary "x86_64-windows" "oauth-mux-x86_64-windows" "oauth-mux-windows-x64" "win32" "x64" "oauth-mux.exe"
package_binary "aarch64-windows" "oauth-mux-aarch64-windows" "oauth-mux-windows-arm64" "win32" "arm64" "oauth-mux.exe"

printf 'writing SHA256SUMS...\n'
write_artifact_checksums

sha_linux_x64="$(hash_file "$artifacts_dir/oauth-mux-x86_64-linux.tar.gz")"
sha_linux_arm64="$(hash_file "$artifacts_dir/oauth-mux-aarch64-linux.tar.gz")"
sha_macos_x64="$(hash_file "$artifacts_dir/oauth-mux-x86_64-macos.tar.gz")"
sha_macos_arm64="$(hash_file "$artifacts_dir/oauth-mux-aarch64-macos.tar.gz")"

printf 'rendering Homebrew formula...\n'
sed \
  -e "s|\${VERSION}|${version}|g" \
  -e "s|\${SHA_LINUX_X64}|${sha_linux_x64}|g" \
  -e "s|\${SHA_LINUX_ARM64}|${sha_linux_arm64}|g" \
  -e "s|\${SHA_MACOS_X64}|${sha_macos_x64}|g" \
  -e "s|\${SHA_MACOS_ARM64}|${sha_macos_arm64}|g" \
  dist/homebrew/oauth-mux.rb >"$homebrew_dir/oauth-mux.rb"

printf 'rendering npm package workspace...\n'
root_pkg_dir="$npm_dir/oauth-mux"
mkdir -p "$root_pkg_dir/bin"
sed "s|0.1.0|${version}|g" dist/npm/package.json >"$root_pkg_dir/package.json"
cp dist/npm/install.js "$root_pkg_dir/install.js"
cp dist/npm/bin/oauth-mux.js "$root_pkg_dir/bin/oauth-mux.js"
chmod 0755 "$root_pkg_dir/bin/oauth-mux.js"

if command -v npm >/dev/null 2>&1; then
  printf 'packing npm tarballs...\n'
  for pkg_json in "$npm_dir"/oauth-mux-{darwin,linux,windows}-*/package.json; do
    npm pack "$(dirname "$pkg_json")" --pack-destination "$npm_tgz_dir" >/dev/null
  done
  npm pack "$root_pkg_dir" --pack-destination "$npm_tgz_dir" >/dev/null
else
  printf 'warning: npm not found; package directories rendered but npm tarballs skipped\n' >&2
fi

write_nfpm_config() {
  local arch="$1"
  local src="$2"
  local config="$nfpm_dir/oauth-mux-${arch}.yaml"
  cat >"$config" <<EOF
name: oauth-mux
arch: "${arch}"
version: "${version}"
maintainer: "Jess Sullivan <jess@sulliwood.org>"
description: "OAuth fallback muxing for AI harness subscriptions"
homepage: "https://github.com/tinyland-inc/oauth-mux"
license: MIT
contents:
  - src: ${src}
    dst: /usr/bin/oauth-mux
    file_info:
      mode: 0755
EOF
}

write_nfpm_config "amd64" "$repo_root/zig-out/x86_64-linux/oauth-mux"
write_nfpm_config "arm64" "$repo_root/zig-out/aarch64-linux/oauth-mux"

if command -v nfpm >/dev/null 2>&1; then
  printf 'building nfpm deb/rpm packages...\n'
  for arch in amd64 arm64; do
    nfpm package -f "$nfpm_dir/oauth-mux-${arch}.yaml" -p deb -t "$artifacts_dir" >/dev/null
    nfpm package -f "$nfpm_dir/oauth-mux-${arch}.yaml" -p rpm -t "$artifacts_dir" >/dev/null
  done
else
  printf 'warning: nfpm not found; deb/rpm artifacts skipped, configs written to %s\n' "$nfpm_dir" >&2
fi

printf 'staging curl installer...\n'
cp dist/install.sh "$artifacts_dir/install.sh"
chmod 0755 "$artifacts_dir/install.sh"
write_artifact_checksums

printf '\nrelease output: %s\n' "$out_dir"
printf 'artifacts:      %s\n' "$artifacts_dir"
printf 'npm workspace:  %s\n' "$npm_dir"
printf 'npm tarballs:   %s\n' "$npm_tgz_dir"
printf 'homebrew:       %s\n' "$homebrew_dir/oauth-mux.rb"
