#!/usr/bin/env sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
project_version="$("$repo_root"/scripts/project-version.sh)"
requested_version="${1:-}"

if [ -z "$requested_version" ]; then
  printf '%s\n' "$project_version"
  exit 0
fi

requested_version="${requested_version#v}"
if [ "$requested_version" != "$project_version" ]; then
  printf 'requested release version %s does not match build.zig.zon version %s\n' \
    "$requested_version" "$project_version" >&2
  exit 2
fi

printf '%s\n' "$project_version"
