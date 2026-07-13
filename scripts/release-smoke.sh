#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# shellcheck source=scripts/release-manifest-current.sh
source "$repo_root/scripts/release-manifest-current.sh"

version="${1:-${VERSION:-$("$repo_root/scripts/project-version.sh")}}"
version="${version#v}"
release_manifest_require_current_v0_1_15 "$version"

out_dir="$repo_root/dist/out/v${version}"
artifacts_dir="$out_dir/artifacts"
homebrew_formula="$out_dir/$(release_manifest_formula_staged_path)"
installer="$out_dir/$(release_manifest_installer_staged_path)"
checksums="$out_dir/$(release_manifest_checksums_staged_path)"
attachment_paths="$(release_manifest_github_attachment_paths)"
archive_rows="$(release_manifest_archive_rows)"
if [ -z "$attachment_paths" ] || [ -z "$archive_rows" ]; then
  printf 'release manifest produced an empty current smoke projection\n' >&2
  exit 1
fi

required_artifacts=()
while IFS= read -r staged_path; do
  case "$staged_path" in
    artifacts/*) required_artifacts+=("${staged_path#artifacts/}") ;;
    *)
      printf 'current GitHub attachment is outside artifacts/: %s\n' "$staged_path" >&2
      exit 1
      ;;
  esac
done <<<"$attachment_paths"

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

printf 'checking release tree: %s\n' "$out_dir"
if [ ! -d "$out_dir" ]; then
  printf 'release output does not exist: %s\n' "$out_dir" >&2
  exit 1
fi
"$repo_root/scripts/check-retired-npm.sh" "$out_dir"

for artifact in "${required_artifacts[@]}"; do
  require_file "$artifacts_dir/$artifact"
done

require_file "$checksums"
require_file "$homebrew_formula"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

printf '%s\n' "${required_artifacts[@]}" | LC_ALL=C sort >"$tmp/expected-artifacts"
: >"$tmp/actual-artifacts"
for artifact in "$artifacts_dir"/*; do
  [ -f "$artifact" ] || continue
  basename "$artifact" >>"$tmp/actual-artifacts"
done
LC_ALL=C sort -o "$tmp/actual-artifacts" "$tmp/actual-artifacts"
if ! diff -u "$tmp/expected-artifacts" "$tmp/actual-artifacts"; then
  printf 'release artifact set differs from the current manifest declaration\n' >&2
  exit 1
fi

printf 'checking checksums...\n'
while read -r expected filename extra; do
  [ -n "${expected:-}" ] || continue
  if [ -n "${extra:-}" ]; then
    printf 'malformed checksum row for %s\n' "$filename" >&2
    exit 1
  fi
  require_file "$artifacts_dir/$filename"
  actual="$(hash_file "$artifacts_dir/$filename")"
  if [ "$actual" != "$expected" ]; then
    printf 'checksum mismatch for %s: expected %s got %s\n' "$filename" "$expected" "$actual" >&2
    exit 1
  fi
done <"$checksums"

: >"$tmp/expected-checksum-members"
for artifact in "${required_artifacts[@]}"; do
  [ "$artifact" = "$(basename "$checksums")" ] && continue
  printf '%s\n' "$artifact" >>"$tmp/expected-checksum-members"
done
LC_ALL=C sort -o "$tmp/expected-checksum-members" "$tmp/expected-checksum-members"
awk 'NF { print $2 }' "$checksums" | LC_ALL=C sort >"$tmp/actual-checksum-members"
if ! diff -u "$tmp/expected-checksum-members" "$tmp/actual-checksum-members"; then
  printf 'checksum membership differs from the current manifest declaration\n' >&2
  exit 1
fi

printf 'checking archive contents...\n'
while IFS=$'\t' read -r target_id _build_dir _target_os staged_path _release_name members_csv; do
  IFS=',' read -r -a expected_members <<<"$members_csv"
  printf '%s\n' "${expected_members[@]}" | LC_ALL=C sort >"$tmp/expected-archive-members"
  tar -tzf "$out_dir/$staged_path" | LC_ALL=C sort >"$tmp/actual-archive-members"
  if ! diff -u "$tmp/expected-archive-members" "$tmp/actual-archive-members"; then
    printf 'archive members differ from manifest for %s\n' "$target_id" >&2
    exit 1
  fi
done <<<"$archive_rows"

printf 'checking Homebrew formula...\n'
if grep -q -E '\$\{(VERSION|SHA_[A-Z0-9_]+)\}' "$homebrew_formula"; then
  printf 'unrendered placeholder remains in %s\n' "$homebrew_formula" >&2
  exit 1
fi
if ! grep -Fqx "  version \"$version\"" "$homebrew_formula"; then
  printf 'Homebrew formula must declare explicit version "%s" so Linux Homebrew does not infer a platform suffix: %s\n' "$version" "$homebrew_formula" >&2
  exit 1
fi
license_line="$(awk '/^[[:space:]]+license / { print NR; exit }' "$homebrew_formula")"
if [ -z "${license_line:-}" ]; then
  printf 'Homebrew formula missing license line: %s\n' "$homebrew_formula" >&2
  exit 1
fi
version_line="$(awk '/^[[:space:]]+version / { print NR; exit }' "$homebrew_formula")"
if [ -z "${version_line:-}" ]; then
  printf 'Homebrew formula missing explicit version line: %s\n' "$homebrew_formula" >&2
  exit 1
fi
if [ "$version_line" -gt "$license_line" ]; then
  printf 'Homebrew formula must put version before license for brew audit style: %s\n' "$homebrew_formula" >&2
  exit 1
fi
"$repo_root/scripts/homebrew-version-check.sh" "$version" "$homebrew_formula"
if grep -q 'bin.install "codex"' "$homebrew_formula"; then
  printf 'Homebrew formula must not install codex; shim lanes must be opt-in outside Brew: %s\n' "$homebrew_formula" >&2
  exit 1
fi
if ! grep -q 'system "test", "!", "-e", "#{bin}/codex"' "$homebrew_formula"; then
  printf 'Homebrew formula test must prove codex is not installed by oauth-mux: %s\n' "$homebrew_formula" >&2
  exit 1
fi
if command -v ruby >/dev/null 2>&1; then
  ruby -c "$homebrew_formula" >/dev/null
fi

native_codex="$tmp/native-codex"
cat >"$native_codex" <<'EOF'
#!/bin/sh
case "$1" in
  --version) echo "native-codex-stub 0.0.0" ;;
  *) echo "native-codex-stub" ;;
esac
EOF
chmod 0755 "$native_codex"

printf 'checking curl installer...\n'
install_dir="$tmp/install-bin"
VERSION="$version" \
  OMUX_RELEASE_BASE_URL="file://$artifacts_dir" \
  INSTALL_DIR="$install_dir" \
  sh "$installer" >/dev/null
"$install_dir/oauth-mux" version | grep -qx "oauth-mux ${version}"
test -x "$install_dir/codex"
grep -q OMUX_CODEX_SHIM "$install_dir/codex"
OMUX_CODEX_BIN="$native_codex" "$install_dir/codex" --version | grep -qx "native-codex-stub 0.0.0"

printf 'release smoke passed for v%s\n' "$version"
