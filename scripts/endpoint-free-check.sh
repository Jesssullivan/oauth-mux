#!/usr/bin/env sh
# endpoint-free-check — grep guard: checked-in Bazel config must carry NO
# remote cache/executor endpoints. Endpoint authority is runtime-only env,
# validated and injected by scripts/gloriousflywheel-bazel.sh:
#
#   BAZEL_REMOTE_CACHE        cache endpoint (grpc/grpcs/http/https)
#   BAZEL_REMOTE_EXECUTOR     executor endpoint (grpc/grpcs/http/https)
#   GF_BAZEL_SUBSTRATE_MODE   shared-cache-backed | executor-backed
#   GF_BAZEL_REMOTE_UPLOAD    true only for trusted cache-writing jobs
#
# Scope: every Bazel config surface the repo carries. Comments are stripped
# before matching so prose like "do not put remote_cache here" cannot trip
# the guard, and real flags cannot hide behind a trailing comment trick.

set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail=0

# ── Guarded file set (explicit; extend when new Bazel config appears) ──
# .bazelrc            main rc, try-imports the two below
# .bazelrc.flywheel   GloriousFlywheel behavior config (endpoint-free by contract)
# user.bazelrc        local-only; must never be committed at all
# MODULE.bazel        Bzlmod module authority
# BUILD.bazel         candidate target graph
# *.bzl               any checked-in Starlark
# .bazelignore        path excludes
# tinyland.repo.json  org repo manifest (names substrate mode, never endpoints)
files=""
for f in $(git ls-files -- '.bazelrc*' '*.bazelrc' 'MODULE.bazel' 'BUILD.bazel' '*.bzl' '.bazelignore' 'tinyland.repo.json'); do
  files="$files $f"
done

if [ -z "${files# }" ]; then
  echo "endpoint-free-check: FAIL — no Bazel config files found (guard is vacuous)" >&2
  exit 1
fi

if git ls-files -- 'user.bazelrc' | grep -q .; then
  echo "endpoint-free-check: FAIL — user.bazelrc is committed; it is a local-only overlay" >&2
  fail=1
fi

# ── Forbidden patterns (explicit guard list) ──
# Each entry: <extended-regex>|<reason>. Matched case-insensitively against
# comment-stripped content.
#
#   grpcs?://                    raw gRPC endpoint literal (any host)
#   --remote_cache(=| )          cache endpoint pinned in config (any scheme,
#                                including https://; = and space-separated flag
#                                forms both) — must come from
#                                BAZEL_REMOTE_CACHE at runtime
#   --remote_executor(=| )       executor endpoint pinned in config — must
#                                come from BAZEL_REMOTE_EXECUTOR at runtime
#   remote_cache/_executor ... https?://
#                                endpoint URL bound to a remote_cache /
#                                remote_executor key in any non-flag shape
#                                (JSON/TOML/Starlark value)
#   --remote_(cache_|exec_)?header(=| )   auth/header material in config — comes
#                                from BAZEL_REMOTE_*HEADER env at runtime
#   --bes_backend(=| )|--bes_results_url(=| )  build-event endpoints pinned in config
#   gf-reapi|gf-rbe              GloriousFlywheel REAPI cell host names
#   svc\.cluster\.local          in-cluster service DNS (GF executor cells)
#   attic-cache-dev|fuzzy-dev|attic\.dev-cluster|attic\.tinyland
#                                stale/live GF attic cache host names
#   [a-z0-9-]+\.ts\.net          tailnet host names
# NOTE: the table is split on "|", so regexes must not use alternation;
# use bracket expressions ([[:space:]=] catches both --flag=v and --flag v).
patterns='
grpcs?://|raw gRPC endpoint literal
--remote_cache[[:space:]=]|remote cache endpoint pinned in config (use BAZEL_REMOTE_CACHE)
--remote_executor[[:space:]=]|remote executor endpoint pinned in config (use BAZEL_REMOTE_EXECUTOR)
remote_cache[^_[:alnum:]].*https?://|remote cache https endpoint value in config (use BAZEL_REMOTE_CACHE)
remote_executor[^_[:alnum:]].*https?://|remote executor https endpoint value in config (use BAZEL_REMOTE_EXECUTOR)
--remote_header[[:space:]=]|remote auth header pinned in config (use BAZEL_REMOTE_HEADER)
--remote_cache_header[[:space:]=]|cache auth header pinned in config (use BAZEL_REMOTE_CACHE_HEADER)
--remote_exec_header[[:space:]=]|executor auth header pinned in config (use BAZEL_REMOTE_EXEC_HEADER)
--bes_backend[[:space:]=]|BES backend endpoint pinned in config
--bes_results_url[[:space:]=]|BES results endpoint pinned in config
gf-reapi|GloriousFlywheel REAPI cell host name
gf-rbe|GloriousFlywheel RBE host name
svc\.cluster\.local|in-cluster service DNS name
attic-cache-dev|GF attic cache host name
fuzzy-dev|GF attic cache host name
attic\.dev-cluster|GF attic cache host name
attic\.tinyland|GF attic cache host name
[a-z0-9-]+\.ts\.net|tailnet host name
'

for f in $files; do
  # Blank out full-line comments (#-first lines in rc files) instead of
  # deleting them so the line count is preserved and the grep -Ein diagnostic
  # below reports true file line numbers.
  stripped="$(sed -E 's/^[[:space:]]*#.*$//' "$f")"
  printf '%s\n' "$patterns" | while IFS='|' read -r regex reason; do
    [ -n "$regex" ] || continue
    if printf '%s\n' "$stripped" | grep -Eiq -- "$regex"; then
      echo "endpoint-free-check: FAIL — $f matches '$regex' ($reason)" >&2
      printf '%s\n' "$stripped" | grep -Ein -- "$regex" | sed "s|^|  $f:|" >&2
      exit 99
    fi
  done || fail=1
done

# ── Positive contract: runtime env authority must exist in the wrapper ──
wrapper="scripts/gloriousflywheel-bazel.sh"
for var in BAZEL_REMOTE_CACHE BAZEL_REMOTE_EXECUTOR GF_BAZEL_SUBSTRATE_MODE GF_BAZEL_REMOTE_UPLOAD; do
  if ! grep -Fq "$var" "$wrapper"; then
    echo "endpoint-free-check: FAIL — $wrapper no longer reads $var (env is the only endpoint authority)" >&2
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "endpoint-free-check: ok — $(echo "$files" | wc -w | tr -d ' ') Bazel config files are endpoint-free; endpoint authority is env-only"
