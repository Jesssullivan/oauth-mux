#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

version="${1:-${VERSION:-$("$repo_root/scripts/project-version.sh")}}"
version="${version#v}"

if [ "${OMUX_REGISTRY_DRY_RUN_CONFIRM:-}" != "registry-dry-run" ]; then
  cat >&2 <<EOF
registry dry-run is disabled.

This command may contact authenticated registry endpoints, but should not publish.
Re-run with:

  OMUX_REGISTRY_DRY_RUN_CONFIRM=registry-dry-run OMUX_REGISTRY_LANES=plan,npm,github,homebrew,system just registry-dry-run ${version}
EOF
  exit 2
fi

out_dir="$repo_root/dist/out/v${version}"
handoff_dir="$out_dir/handoff"
report="$handoff_dir/registry-dry-run.md"
tmp_files=()
tmp_taps=()

cleanup() {
  for file in "${tmp_files[@]}"; do
    rm -f "$file"
  done
  if command -v brew >/dev/null 2>&1; then
    for tap in "${tmp_taps[@]}"; do
      brew untap "$tap" >/dev/null 2>&1 || true
    done
  fi
}
trap cleanup EXIT

if [ ! -d "$out_dir" ]; then
  printf 'release output does not exist: %s\n' "$out_dir" >&2
  printf 'run: just release-proof %s\n' "$version" >&2
  exit 1
fi

mkdir -p "$handoff_dir"

lanes_csv="${OMUX_REGISTRY_LANES:-plan}"
IFS=',' read -r -a lanes <<<"$lanes_csv"

append() {
  printf '%s\n' "$*" >>"$report"
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'missing required command for lane: %s\n' "$1" >&2
    exit 1
  fi
}

generated_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
cat >"$report" <<EOF
# oauth-mux v${version} Registry Dry-Run

Generated: ${generated_at}
Release tree: \`dist/out/v${version}\`

This report records non-publishing registry checks. It must not include tokens.

EOF

for lane in "${lanes[@]}"; do
  case "$lane" in
    plan)
      append "## plan"
      append
      append "- release tree exists"
      append "- publish list: \`dist/out/v${version}/handoff/publish-files.txt\`"
      append "- full checksums: \`dist/out/v${version}/handoff/SHA256SUMS.full\`"
      append
      ;;

    github)
      require_command gh
      append "## github"
      append
      gh auth status >/dev/null
      if gh release view "v${version}" >/dev/null 2>&1; then
        append "- authenticated gh session OK"
        append "- release v${version} already exists"
      else
        append "- authenticated gh session OK"
        append "- release v${version} does not exist yet; tag release workflow remains publication path"
      fi
      append
      ;;

    npm)
      require_command npm
      npmrc="$(mktemp)"
      tmp_files+=("$npmrc")
      "$repo_root/scripts/resolve-npm-token.sh" --npmrc "$npmrc" >/dev/null
      append "## npm"
      append
      NPM_CONFIG_USERCONFIG="$npmrc" npm whoami --registry=https://registry.npmjs.org/ >/dev/null
      for tarball in "$out_dir"/npm-tarballs/*.tgz; do
        name="$(basename "$tarball")"
        publish_log="$(mktemp)"
        tmp_files+=("$publish_log")
        if NPM_CONFIG_USERCONFIG="$npmrc" npm publish "$tarball" --dry-run --access public ${OMUX_NPM_EXTRA_ARGS:-} >"$publish_log" 2>&1; then
          append "- dry-run OK: \`npm-tarballs/${name}\`"
          continue
        fi

        package_name="${name%-${version}.tgz}"
        if grep -qi 'previously published versions' "$publish_log" &&
          NPM_CONFIG_USERCONFIG="$npmrc" npm view "${package_name}@${version}" version --registry=https://registry.npmjs.org/ >/dev/null 2>&1; then
          append "- already published OK: \`${package_name}@${version}\`"
          continue
        fi

        cat "$publish_log" >&2
        exit 1
      done
      append
      ;;

    homebrew)
      brew_cmd="${OMUX_BREW_BIN:-brew}"
      require_command "$brew_cmd"
      if [ -z "${OMUX_HOMEBREW_TAP_DIR:-}" ]; then
        printf 'homebrew lane requires OMUX_HOMEBREW_TAP_DIR\n' >&2
        exit 1
      fi
      formula="$out_dir/homebrew/oauth-mux.rb"
      tap_formula="$OMUX_HOMEBREW_TAP_DIR/Formula/oauth-mux.rb"
      mkdir -p "$(dirname "$tap_formula")"
      cp "$formula" "$tap_formula"
      git -C "$OMUX_HOMEBREW_TAP_DIR" diff --check -- Formula/oauth-mux.rb
      audit_log="$(mktemp)"
      tmp_files+=("$audit_log")
      audit_args=(audit --formula --strict)
      audit_label="brew audit --strict"
      if [ "${OMUX_HOMEBREW_AUDIT_ONLINE:-0}" = "1" ]; then
        audit_args+=(--online)
        audit_label="brew audit --strict --online"
      fi
      tap_name="${OMUX_HOMEBREW_TAP_NAME:-}"
      if [ -z "$tap_name" ]; then
        tap_name="tinyland-inc/oauth-mux-dry-run-$$"
        tmp_taps+=("$tap_name")
      fi
      "$brew_cmd" tap "$tap_name" "$OMUX_HOMEBREW_TAP_DIR" >/dev/null
      tapped_repo="$("$brew_cmd" --repository "$tap_name")"
      mkdir -p "$tapped_repo/Formula"
      cp "$formula" "$tapped_repo/Formula/oauth-mux.rb"
      if ! "$brew_cmd" "${audit_args[@]}" "${tap_name}/oauth-mux" >"$audit_log" 2>&1; then
        cat "$audit_log" >&2
        exit 1
      fi
      append "## homebrew"
      append
      append "- formula copied to tap checkout"
      append "- git diff --check OK"
      append "- ${audit_label} OK via \`${tap_name}/oauth-mux\`"
      append
      ;;

    system)
      append "## system packages"
      append
      if command -v dpkg-deb >/dev/null 2>&1; then
        for deb in "$out_dir"/artifacts/*.deb; do
          dpkg-deb --info "$deb" >/dev/null
          append "- deb metadata OK: \`artifacts/$(basename "$deb")\`"
        done
      else
        append "- dpkg-deb unavailable; skipped deb metadata check"
      fi
      if command -v rpm >/dev/null 2>&1; then
        for rpm_pkg in "$out_dir"/artifacts/*.rpm; do
          rpm -qp "$rpm_pkg" >/dev/null
          append "- rpm metadata OK: \`artifacts/$(basename "$rpm_pkg")\`"
        done
      else
        append "- rpm unavailable; skipped rpm metadata check"
      fi
      append
      ;;

    *)
      printf 'unknown registry dry-run lane: %s\n' "$lane" >&2
      exit 1
      ;;
  esac
done

printf 'registry dry-run report: %s\n' "$report"
