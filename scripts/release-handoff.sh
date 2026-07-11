#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

version="${1:-${VERSION:-$("$repo_root/scripts/project-version.sh")}}"
version="${version#v}"

out_dir="$repo_root/dist/out/v${version}"
artifacts_dir="$out_dir/artifacts"
homebrew_formula="$out_dir/homebrew/oauth-mux.rb"
handoff_dir="$out_dir/handoff"
handoff_file="$handoff_dir/release-handoff.md"
publish_files="$handoff_dir/publish-files.txt"
full_checksums="$handoff_dir/SHA256SUMS.full"

binary_tarballs=(
  "oauth-mux-x86_64-linux.tar.gz"
  "oauth-mux-aarch64-linux.tar.gz"
  "oauth-mux-x86_64-macos.tar.gz"
  "oauth-mux-aarch64-macos.tar.gz"
  "oauth-mux-x86_64-windows.tar.gz"
  "oauth-mux-aarch64-windows.tar.gz"
)

system_packages=(
  "oauth-mux_${version}_amd64.deb"
  "oauth-mux_${version}_arm64.deb"
  "oauth-mux-${version}-1.x86_64.rpm"
  "oauth-mux-${version}-1.aarch64.rpm"
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
    printf 'missing release handoff input: %s\n' "$1" >&2
    exit 1
  fi
}

relative_to_out() {
  printf '%s\n' "${1#"$out_dir"/}"
}

table_row() {
  local path="$1"
  local rel
  rel="$(relative_to_out "$path")"
  printf '| `%s` | `%s` |\n' "$rel" "$(hash_file "$path")" >>"$handoff_file"
}

if [ ! -d "$out_dir" ]; then
  printf 'release output does not exist: %s\n' "$out_dir" >&2
  printf 'run: just release-local %s\n' "$version" >&2
  exit 1
fi
"$repo_root/scripts/check-retired-npm.sh" "$out_dir"

require_file "$artifacts_dir/SHA256SUMS"
require_file "$artifacts_dir/install.sh"
require_file "$homebrew_formula"
require_file "$out_dir/nfpm/oauth-mux-amd64.yaml"
require_file "$out_dir/nfpm/oauth-mux-arm64.yaml"

for artifact in "${binary_tarballs[@]}" "${system_packages[@]}"; do
  require_file "$artifacts_dir/$artifact"
done

mkdir -p "$handoff_dir"

: >"$publish_files"
for artifact in "${binary_tarballs[@]}" "${system_packages[@]}" "SHA256SUMS" "install.sh"; do
  printf '%s\n' "artifacts/$artifact" >>"$publish_files"
done
printf '%s\n' "homebrew/oauth-mux.rb" >>"$publish_files"

: >"$full_checksums"
while read -r rel; do
  path="$out_dir/$rel"
  require_file "$path"
  printf '%s  %s\n' "$(hash_file "$path")" "$rel" >>"$full_checksums"
done <"$publish_files"

generated_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
git_commit="$(git rev-parse --short HEAD 2>/dev/null || printf 'unknown')"

cat >"$handoff_file" <<EOF
# oauth-mux v${version} Release Handoff

Generated: ${generated_at}
Source commit: ${git_commit}
Release tree: \`dist/out/v${version}\`

This handoff is non-publishing. It proves and lists the files an operator would
publish after \`just release-proof ${version}\` has passed.

## Required Proofs

- Local proof: \`just release-proof ${version}\`
- Hosted tag proof: \`.github/workflows/release.yml\`
- Optional self-hosted proof after the workflow exists on \`main\`:
  \`gh workflow run release-proof.yml -f version=${version}\`

During runner or lab outages, treat a queued self-hosted proof as deferred
evidence. Do not claim GloriousFlywheel cache-first proof unless the
\`tinyland-nix\` job actually checks out the private action and runs.

## GitHub Release Attachments

Attach these files from \`dist/out/v${version}\`:

| File | SHA256 |
| --- | --- |
EOF

for artifact in "${binary_tarballs[@]}" "${system_packages[@]}" "install.sh" "SHA256SUMS"; do
  table_row "$artifacts_dir/$artifact"
done

cat >>"$handoff_file" <<EOF

## Homebrew Tap

Copy the rendered formula into the public tap
\`Jesssullivan/homebrew-omux\` and review the four platform checksums:

\`\`\`bash
cp dist/out/v${version}/homebrew/oauth-mux.rb <tap-checkout>/Formula/oauth-mux.rb
git -C <tap-checkout> diff -- Formula/oauth-mux.rb
\`\`\`

Formula file:

| File | SHA256 |
| --- | --- |
EOF

table_row "$homebrew_formula"

cat >>"$handoff_file" <<EOF

## deb/rpm Handoff

Publish these files to the package repository or attach them to the GitHub
release until a repository is selected:

| File | SHA256 |
| --- | --- |
EOF

for artifact in "${system_packages[@]}"; do
  table_row "$artifacts_dir/$artifact"
done

cat >>"$handoff_file" <<EOF

## Generated Files

- \`handoff/release-handoff.md\`: this operator handoff
- \`handoff/publish-files.txt\`: relative file list for publishing scripts
- \`handoff/SHA256SUMS.full\`: checksums for GitHub, Homebrew, deb, and rpm handoff files

## Boundary

This step does not use Homebrew, package-repository, or GitHub release write
credentials. npm publication is retired and npm artifacts are forbidden from
the staged release tree.
EOF

printf 'release handoff written:\n'
printf '  %s\n' "$handoff_file"
printf '  %s\n' "$publish_files"
printf '  %s\n' "$full_checksums"
