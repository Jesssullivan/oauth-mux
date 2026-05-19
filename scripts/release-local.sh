#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

project_version="$("$repo_root/scripts/project-version.sh")"
version="${1:-${VERSION:-$project_version}}"
version="${version#v}"
if [ "$version" != "$project_version" ]; then
  printf 'release version %s does not match build.zig.zon version %s\n' "$version" "$project_version" >&2
  printf 'bump build.zig.zon before staging a differently versioned release\n' >&2
  exit 2
fi

out_dir="$repo_root/dist/out/v${version}"
artifacts_dir="$out_dir/artifacts"
npm_dir="$out_dir/npm"
npm_tgz_dir="$out_dir/npm-tarballs"
homebrew_dir="$out_dir/homebrew"
nfpm_dir="$out_dir/nfpm"
work_dir="$out_dir/work"

format_kib_as_gib() {
  awk "BEGIN { printf \"%.1f\", $1 / 1048576 }"
}

host_memory_bytes() {
  if command -v sysctl >/dev/null 2>&1; then
    sysctl -n hw.memsize 2>/dev/null && return 0
  fi
  if [ -r /proc/meminfo ]; then
    awk '/^MemTotal:/ { printf "%.0f\n", $2 * 1024; exit }' /proc/meminfo
    return 0
  fi
  return 1
}

release_host_preflight() {
  if [ "${OMUX_RELEASE_SKIP_PREFLIGHT:-0}" = "1" ]; then
    printf 'warning: skipping release host preflight because OMUX_RELEASE_SKIP_PREFLIGHT=1\n' >&2
    return
  fi

  local free_kib min_free_kib
  free_kib="$(df -Pk "$repo_root" | awk 'NR == 2 { print $4 }')"
  min_free_kib="${OMUX_RELEASE_MIN_FREE_KIB:-12582912}"
  if [ -n "$free_kib" ] && [ "$free_kib" -lt "$min_free_kib" ]; then
    if [ "${OMUX_RELEASE_ALLOW_LOW_DISK:-0}" != "1" ]; then
      printf 'release host preflight failed: only %s GiB free at %s; need at least %s GiB for local release proof\n' \
        "$(format_kib_as_gib "$free_kib")" "$repo_root" "$(format_kib_as_gib "$min_free_kib")" >&2
      printf 'free disk space, use remote CI/RBE release proof, or set OMUX_RELEASE_ALLOW_LOW_DISK=1 to continue anyway\n' >&2
      exit 2
    fi
    printf 'warning: continuing with only %s GiB free because OMUX_RELEASE_ALLOW_LOW_DISK=1\n' \
      "$(format_kib_as_gib "$free_kib")" >&2
  fi

  local mem_bytes low_mem_bytes
  low_mem_bytes=$((12 * 1024 * 1024 * 1024))
  mem_bytes="$(host_memory_bytes 2>/dev/null || true)"
  if [ -n "$mem_bytes" ] && [ "$mem_bytes" -lt "$low_mem_bytes" ] && [ -z "${OMUX_RELEASE_ZIG_JOBS:-}" ]; then
    OMUX_RELEASE_ZIG_JOBS=2
    export OMUX_RELEASE_ZIG_JOBS
    printf 'release host preflight: detected less than 12 GiB RAM; using zig -j%s for local release proof\n' \
      "$OMUX_RELEASE_ZIG_JOBS" >&2
  fi
}

release_host_preflight
if [ "${OMUX_RELEASE_PREFLIGHT_ONLY:-0}" = "1" ]; then
  printf 'release host preflight passed\n'
  exit 0
fi

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
  if [ "$npm_os" = "darwin" ] || [ "$npm_os" = "linux" ]; then
    cp "$repo_root/dist/codex-shim.sh" "$stage/codex"
    chmod 0755 "$stage/codex"
    tar -czf "$artifacts_dir/${artifact}.tar.gz" -C "$stage" "$binary_name" codex
  else
    tar -czf "$artifacts_dir/${artifact}.tar.gz" -C "$stage" "$binary_name"
  fi

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
  "repository": "Jesssullivan/oauth-mux",
  "homepage": "https://omux.xoxd.ai",
  "os": ["${npm_os}"],
  "cpu": ["${npm_cpu}"],
  "files": ["bin"]
}
EOF
}

printf 'building release binaries...\n'
zig_release_args=(build release --summary all)
if [ -n "${OMUX_RELEASE_ZIG_JOBS:-}" ]; then
  zig_release_args+=("-j${OMUX_RELEASE_ZIG_JOBS}")
fi
printf 'running: zig %s\n' "${zig_release_args[*]}"
zig "${zig_release_args[@]}"

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
sed -E \
  -e "s|(\"version\": \")[^\"]+(\")|\\1${version}\\2|" \
  -e "s|(\"oauth-mux-[^\"]+\": \")[^\"]+(\")|\\1${version}\\2|" \
  dist/npm/package.json >"$root_pkg_dir/package.json"
cp dist/npm/install.js "$root_pkg_dir/install.js"
cp dist/npm/bin/oauth-mux.js "$root_pkg_dir/bin/oauth-mux.js"
cp dist/npm/bin/codex.js "$root_pkg_dir/bin/codex.js"
chmod 0755 "$root_pkg_dir/bin/oauth-mux.js"
chmod 0755 "$root_pkg_dir/bin/codex.js"

if command -v npm >/dev/null 2>&1; then
  printf 'packing npm tarballs...\n'
  export npm_config_cache="${npm_config_cache:-$work_dir/npm-cache}"
  export npm_config_update_notifier=false
  mkdir -p "$npm_config_cache"
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
  local codex_shim="$work_dir/nfpm-codex-shim"
  cp "$repo_root/dist/codex-shim.sh" "$codex_shim"
  chmod 0755 "$codex_shim"
  cat >"$config" <<EOF
name: oauth-mux
arch: "${arch}"
version: "${version}"
maintainer: "Jess Sullivan <jess@sulliwood.org>"
description: "OAuth fallback muxing for AI harness subscriptions"
homepage: "https://omux.xoxd.ai"
license: MIT
contents:
  - src: ${src}
    dst: /usr/bin/oauth-mux
    file_info:
      mode: 0755
  - src: ${codex_shim}
    dst: /usr/bin/codex
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
