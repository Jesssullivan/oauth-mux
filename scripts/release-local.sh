#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# shellcheck source=scripts/release-manifest-current.sh
source "$repo_root/scripts/release-manifest-current.sh"

project_version="$("$repo_root/scripts/project-version.sh")"
version="${1:-${VERSION:-$project_version}}"
version="${version#v}"
if [ "$version" != "$project_version" ]; then
  printf 'release version %s does not match build.zig.zon version %s\n' "$version" "$project_version" >&2
  printf 'bump build.zig.zon before staging a differently versioned release\n' >&2
  exit 2
fi
release_manifest_require_current_v0_1_15 "$version"

# TIN-2462: a release cut is not proof-complete without a CHANGELOG entry
# for the version being cut. Fail the cut here, not on every PR.
if [ "${OMUX_RELEASE_SKIP_CHANGELOG_GATE:-0}" != "1" ]; then
  "$repo_root/scripts/check-changelog-entry.sh" "$version"
fi

out_dir="$repo_root/dist/out/v${version}"
artifacts_dir="$out_dir/artifacts"
homebrew_dir="$out_dir/homebrew"
nfpm_dir="$out_dir/nfpm"
work_dir="$out_dir/work"
checksums_path="$out_dir/$(release_manifest_checksums_staged_path)"
installer_path="$out_dir/$(release_manifest_installer_staged_path)"
archive_rows="$(release_manifest_archive_rows)"
package_rows="$(release_manifest_package_rows)"
if [ -z "$archive_rows" ] || [ -z "$package_rows" ]; then
  printf 'release manifest produced an empty current packaging projection\n' >&2
  exit 1
fi

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
mkdir -p "$artifacts_dir" "$homebrew_dir" "$nfpm_dir" "$work_dir"
"$repo_root/scripts/check-retired-npm.sh" "$out_dir"

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  else
    shasum -a 256 "$1" | awk '{ print $1 }'
  fi
}

write_artifact_checksums() {
  : >"$checksums_path"
  for artifact in "$artifacts_dir"/*; do
    [ -f "$artifact" ] || continue
    [ "$artifact" = "$checksums_path" ] && continue
    printf '%s  %s\n' "$(hash_file "$artifact")" "$(basename "$artifact")" >>"$checksums_path"
  done
}

package_archive() {
  local target_id="$1"
  local build_dir="$2"
  local staged_path="$3"
  local members_csv="$4"
  local stage="$work_dir/archive-${target_id}"
  local members=()
  local member src

  IFS=',' read -r -a members <<<"$members_csv"
  mkdir -p "$stage"
  for member in "${members[@]}"; do
    case "$member" in
      oauth-mux|oauth-mux.exe)
        src="$repo_root/zig-out/${build_dir}/${member}"
        ;;
      codex)
        src="$repo_root/dist/codex-shim.sh"
        ;;
      *)
        printf 'unsupported current archive member for %s: %s\n' "$target_id" "$member" >&2
        exit 1
        ;;
    esac
    if [ ! -f "$src" ]; then
      printf 'missing release archive input: %s\n' "$src" >&2
      exit 1
    fi
    cp "$src" "$stage/$member"
    chmod 0755 "$stage/$member"
  done

  tar -czf "$out_dir/$staged_path" -C "$stage" "${members[@]}"
}

printf 'building release binaries...\n'
zig_release_args=(build release --summary all)
if [ -n "${OMUX_RELEASE_ZIG_JOBS:-}" ]; then
  zig_release_args+=("-j${OMUX_RELEASE_ZIG_JOBS}")
fi
printf 'running: zig %s\n' "${zig_release_args[*]}"
zig "${zig_release_args[@]}"

while IFS=$'\t' read -r target_id build_dir _target_os staged_path _release_name members_csv; do
  package_archive "$target_id" "$build_dir" "$staged_path" "$members_csv"
done <<<"$archive_rows"

printf 'writing SHA256SUMS...\n'
write_artifact_checksums

sha_linux_x64="$(hash_file "$out_dir/$(release_manifest_archive_staged_path x86_64-linux)")"
sha_linux_arm64="$(hash_file "$out_dir/$(release_manifest_archive_staged_path aarch64-linux)")"
sha_macos_x64="$(hash_file "$out_dir/$(release_manifest_archive_staged_path x86_64-macos)")"
sha_macos_arm64="$(hash_file "$out_dir/$(release_manifest_archive_staged_path aarch64-macos)")"
homebrew_formula="$out_dir/$(release_manifest_formula_staged_path)"

printf 'rendering Homebrew formula...\n'
sed \
  -e "s|\${VERSION}|${version}|g" \
  -e "s|\${SHA_LINUX_X64}|${sha_linux_x64}|g" \
  -e "s|\${SHA_LINUX_ARM64}|${sha_linux_arm64}|g" \
  -e "s|\${SHA_MACOS_X64}|${sha_macos_x64}|g" \
  -e "s|\${SHA_MACOS_ARM64}|${sha_macos_arm64}|g" \
  dist/homebrew/oauth-mux.rb >"$homebrew_formula"

write_nfpm_config() {
  local build_dir="$1"
  local cpu_arch="$2"
  local members_csv="$3"
  local nfpm_arch member src
  local members=()

  case "$cpu_arch" in
    x86_64) nfpm_arch="amd64" ;;
    aarch64) nfpm_arch="arm64" ;;
    *)
      printf 'unsupported nfpm cpu architecture: %s\n' "$cpu_arch" >&2
      exit 1
      ;;
  esac
  local config="$nfpm_dir/oauth-mux-${nfpm_arch}.yaml"
  [ -f "$config" ] && return

  cat >"$config" <<EOF
name: oauth-mux
arch: "${nfpm_arch}"
version: "${version}"
maintainer: "Jess Sullivan <jess@sulliwood.org>"
description: "OAuth fallback muxing for AI harness subscriptions"
homepage: "https://omux.xoxd.ai"
license: MIT
contents:
EOF

  IFS=',' read -r -a members <<<"$members_csv"
  for member in "${members[@]}"; do
    case "$member" in
      /usr/bin/oauth-mux)
        src="$repo_root/zig-out/${build_dir}/oauth-mux"
        ;;
      /usr/bin/codex)
        src="$work_dir/nfpm-codex-shim"
        if [ ! -f "$src" ]; then
          cp "$repo_root/dist/codex-shim.sh" "$src"
          chmod 0755 "$src"
        fi
        ;;
      *)
        printf 'unsupported current system-package member: %s\n' "$member" >&2
        exit 1
        ;;
    esac
    if [ ! -f "$src" ]; then
      printf 'missing nfpm input: %s\n' "$src" >&2
      exit 1
    fi
    cat >>"$config" <<EOF
  - src: ${src}
    dst: ${member}
    file_info:
      mode: 0755
EOF
  done
}

while IFS=$'\t' read -r _kind _target_id build_dir cpu_arch _staged_path _release_name members_csv; do
  write_nfpm_config "$build_dir" "$cpu_arch" "$members_csv"
done <<<"$package_rows"

if command -v nfpm >/dev/null 2>&1; then
  printf 'building nfpm deb/rpm packages...\n'
  while IFS=$'\t' read -r kind _target_id _build_dir cpu_arch staged_path release_name _members_csv; do
    case "$cpu_arch" in
      x86_64) nfpm_arch="amd64" ;;
      aarch64) nfpm_arch="arm64" ;;
    esac
    nfpm package -f "$nfpm_dir/oauth-mux-${nfpm_arch}.yaml" -p "$kind" -t "$artifacts_dir" >/dev/null
    if [ ! -f "$out_dir/$staged_path" ]; then
      printf 'nfpm did not emit manifest-declared artifact %s (%s)\n' "$release_name" "$staged_path" >&2
      exit 1
    fi
  done <<<"$package_rows"
else
  printf 'warning: nfpm not found; deb/rpm artifacts skipped, configs written to %s\n' "$nfpm_dir" >&2
fi

printf 'staging curl installer...\n'
cp dist/install.sh "$installer_path"
chmod 0755 "$installer_path"
write_artifact_checksums

printf '\nrelease output: %s\n' "$out_dir"
printf 'artifacts:      %s\n' "$artifacts_dir"
printf 'homebrew:       %s\n' "$homebrew_formula"
