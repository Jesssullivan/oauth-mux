#!/usr/bin/env sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

awk -F'"' '
  /^[[:space:]]*\.version[[:space:]]*=/ {
    print $2
    found = 1
    exit
  }
  END {
    if (!found) exit 1
  }
' "$repo_root/build.zig.zon"
