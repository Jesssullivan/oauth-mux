#!/usr/bin/env bash
# Spoke-side Bazel wrapper for oauth-mux's bounded GloriousFlywheel REAPI work.
#
# Endpoint values come from the environment and are passed as explicit Bazel
# flags. Checked-in .bazelrc files are not cache/executor authority.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
flywheel_env="${repo_root}/.env.flywheel.local"
if [[ -f "${flywheel_env}" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "${flywheel_env}"
  set +a
fi

usage() {
  cat >&2 <<'EOF'
Usage: scripts/gloriousflywheel-bazel.sh <command> [args...]

Commands:
  info   Validate cache attachment, then run bazel info
  build  Run a GloriousFlywheel-backed Bazel build
  test   Build a GloriousFlywheel-backed target that runs `zig build test`

Required environment:
  BAZEL_REMOTE_CACHE        grpc://, grpcs://, http://, or https:// endpoint
  GF_BAZEL_SUBSTRATE_MODE   shared-cache-backed or executor-backed

Executor-backed mode also requires:
  BAZEL_REMOTE_EXECUTOR     grpc://, grpcs://, http://, or https:// endpoint

Optional environment:
  BAZEL_BIN                         Bazel executable, defaults to bazelisk
  GF_BAZEL_REMOTE_UPLOAD            true only for trusted cache-writing jobs
  GF_BAZEL_FORCE_EXECUTION          true adds --remote_accept_cached=false
  GF_BAZEL_REMOTE_EXECUTION_PLATFORM
                                    defaults to gloriousflywheel-rbe-linux-x86_64
  BAZEL_REMOTE_EXECUTOR_CACHE       executor-readable CAS/cache endpoint
  BAZEL_CREDENTIAL_HELPER           Bazel credential helper, one per line
  BAZEL_REMOTE_HEADER               remote header as name=value, one per line
  BAZEL_REMOTE_CACHE_HEADER         cache-only header as name=value, one per line
  BAZEL_REMOTE_EXEC_HEADER          executor-only header as name=value, one per line
  BAZEL_REMOTE_MAX_CONNECTIONS      cap remote gRPC connections
  GF_BAZEL_JOBS                     Bazel jobs override
  BAZEL_OUTPUT_USER_ROOT            isolated Bazel output user root
  BAZEL_OUTPUT_BASE                 isolated Bazel output base
  BAZEL_REPOSITORY_CACHE            Bazel repository cache directory
  BAZEL_DISTDIR                     colon-separated Bazel distdir paths
EOF
}

if [[ $# -lt 1 ]]; then
  usage
  exit 2
fi

command="$1"
shift

case "${command}" in
info | build | test) ;;
-h | --help)
  usage
  exit 0
  ;;
*)
  echo "ERROR: unsupported Bazel command for GloriousFlywheel wrapper: ${command}" >&2
  usage
  exit 2
  ;;
esac

bazel_bin="${BAZEL_BIN:-bazelisk}"
remote_cache="${BAZEL_REMOTE_CACHE:-}"
remote_executor="${BAZEL_REMOTE_EXECUTOR:-}"
remote_executor_cache="${BAZEL_REMOTE_EXECUTOR_CACHE:-}"
mode="${GF_BAZEL_SUBSTRATE_MODE:-}"
upload="${GF_BAZEL_REMOTE_UPLOAD:-false}"
force_execution="${GF_BAZEL_FORCE_EXECUTION:-false}"
remote_execution_platform="${GF_BAZEL_REMOTE_EXECUTION_PLATFORM:-gloriousflywheel-rbe-linux-x86_64}"
remote_max_connections="${BAZEL_REMOTE_MAX_CONNECTIONS:-}"
jobs="${GF_BAZEL_JOBS:-}"

startup_args=()
external_fetch_args=()
executor_args=()
auth_args=()
cache_auth_args=()
exec_auth_args=()

validate_runtime_value() {
  local flag_name="$1"
  local value="$2"

  if [[ ${value} == *'${'* ]] || [[ ${value} == *'}'* ]]; then
    echo "ERROR: ${flag_name} contains a literal shell placeholder, not a real value." >&2
    exit 1
  fi
}

validate_endpoint() {
  local name="$1"
  local value="$2"

  validate_runtime_value "${name}" "${value}"
  if [[ ${value} =~ (attic-cache-dev|fuzzy-dev|attic\.dev-cluster|attic\.tinyland) ]]; then
    echo "ERROR: ${name} points at a stale GloriousFlywheel endpoint." >&2
    exit 1
  fi
  if [[ ! ${value} =~ ^(grpc|grpcs|http|https):// ]]; then
    echo "ERROR: ${name} must start with grpc://, grpcs://, http://, or https://." >&2
    exit 1
  fi
}

if [[ -n ${BAZEL_OUTPUT_USER_ROOT:-} ]]; then
  startup_args+=(--output_user_root="${BAZEL_OUTPUT_USER_ROOT}")
fi

if [[ -n ${BAZEL_OUTPUT_BASE:-} ]]; then
  startup_args+=(--output_base="${BAZEL_OUTPUT_BASE}")
fi

if [[ -n ${BAZEL_REPOSITORY_CACHE:-} ]]; then
  external_fetch_args+=(--repository_cache="${BAZEL_REPOSITORY_CACHE}")
fi

while IFS= read -r credential_helper; do
  if [[ -n ${credential_helper} ]]; then
    validate_runtime_value "BAZEL_CREDENTIAL_HELPER" "${credential_helper}"
    auth_args+=(--credential_helper="${credential_helper}")
  fi
done <<<"${BAZEL_CREDENTIAL_HELPER:-}"

while IFS= read -r remote_header; do
  if [[ -n ${remote_header} ]]; then
    validate_runtime_value "BAZEL_REMOTE_HEADER" "${remote_header}"
    auth_args+=(--remote_header="${remote_header}")
  fi
done <<<"${BAZEL_REMOTE_HEADER:-}"

while IFS= read -r remote_cache_header; do
  if [[ -n ${remote_cache_header} ]]; then
    validate_runtime_value "BAZEL_REMOTE_CACHE_HEADER" "${remote_cache_header}"
    cache_auth_args+=(--remote_cache_header="${remote_cache_header}")
  fi
done <<<"${BAZEL_REMOTE_CACHE_HEADER:-}"

while IFS= read -r remote_exec_header; do
  if [[ -n ${remote_exec_header} ]]; then
    validate_runtime_value "BAZEL_REMOTE_EXEC_HEADER" "${remote_exec_header}"
    exec_auth_args+=(--remote_exec_header="${remote_exec_header}")
  fi
done <<<"${BAZEL_REMOTE_EXEC_HEADER:-}"

if [[ -n ${BAZEL_DISTDIR:-} ]]; then
  IFS=: read -r -a bazel_distdirs <<<"${BAZEL_DISTDIR}"
  for bazel_distdir in "${bazel_distdirs[@]}"; do
    if [[ -n ${bazel_distdir} ]]; then
      external_fetch_args+=(--distdir="${bazel_distdir}")
    fi
  done
fi

if [[ -z ${remote_cache} ]]; then
  echo "ERROR: BAZEL_REMOTE_CACHE is required for GloriousFlywheel-backed Bazel work." >&2
  exit 1
fi
validate_endpoint "BAZEL_REMOTE_CACHE" "${remote_cache}"

case "${mode}" in
shared-cache-backed)
  if [[ -n ${remote_executor} ]]; then
    echo "ERROR: BAZEL_REMOTE_EXECUTOR is set but GF_BAZEL_SUBSTRATE_MODE is shared-cache-backed." >&2
    exit 1
  fi
  bazel_config="flywheel"
  ;;
executor-backed)
  if [[ -z ${remote_executor} ]]; then
    echo "ERROR: executor-backed mode requires BAZEL_REMOTE_EXECUTOR." >&2
    exit 1
  fi
  validate_endpoint "BAZEL_REMOTE_EXECUTOR" "${remote_executor}"
  if [[ -n ${remote_executor_cache} ]]; then
    validate_endpoint "BAZEL_REMOTE_EXECUTOR_CACHE" "${remote_executor_cache}"
  fi
  bazel_config="flywheel-executor"
  remote_cache="${remote_executor_cache:-${remote_executor}}"
  executor_args+=(
    --remote_executor="${remote_executor}"
    --remote_local_fallback=false
    --spawn_strategy=remote
    --remote_default_exec_properties="gf.platform=${remote_execution_platform}"
  )
  if [[ -n ${remote_max_connections} ]]; then
    executor_args+=(--remote_max_connections="${remote_max_connections}")
  fi
  if [[ -n ${jobs} ]]; then
    executor_args+=(--jobs="${jobs}")
  fi
  ;;
*)
  echo "ERROR: GF_BAZEL_SUBSTRATE_MODE must be shared-cache-backed or executor-backed." >&2
  exit 1
  ;;
esac

case "${upload}" in
true | 1 | yes)
  upload_args=(--remote_upload_local_results=true)
  ;;
false | 0 | no | "")
  upload_args=(--remote_upload_local_results=false)
  ;;
*)
  echo "ERROR: GF_BAZEL_REMOTE_UPLOAD must be true or false." >&2
  exit 1
  ;;
esac

case "${force_execution}" in
true | 1 | yes)
  force_args=(--remote_accept_cached=false)
  ;;
false | 0 | no | "")
  force_args=()
  ;;
*)
  echo "ERROR: GF_BAZEL_FORCE_EXECUTION must be true or false." >&2
  exit 1
  ;;
esac

if ! command -v "${bazel_bin}" >/dev/null 2>&1; then
  echo "ERROR: ${bazel_bin} is not on PATH; enter direnv or nix develop first." >&2
  exit 127
fi

bazel_action="${command}"
if [[ ${command} == "test" ]]; then
  bazel_action="build"
fi

case "${command}" in
info)
  bazel_args=(
    info
    --remote_cache="${remote_cache}"
    ${upload_args[@]+"${upload_args[@]}"}
    ${auth_args[@]+"${auth_args[@]}"}
    ${cache_auth_args[@]+"${cache_auth_args[@]}"}
  )
  ;;
build | test)
  bazel_args=(
    "${bazel_action}"
    --config="${bazel_config}"
    --remote_cache="${remote_cache}"
    ${upload_args[@]+"${upload_args[@]}"}
    ${force_args[@]+"${force_args[@]}"}
    ${auth_args[@]+"${auth_args[@]}"}
    ${cache_auth_args[@]+"${cache_auth_args[@]}"}
    ${exec_auth_args[@]+"${exec_auth_args[@]}"}
    ${executor_args[@]+"${executor_args[@]}"}
    ${external_fetch_args[@]+"${external_fetch_args[@]}"}
  )
  ;;
esac

exec_args=("${bazel_bin}")
if [[ ${#startup_args[@]} -gt 0 ]]; then
  exec_args+=(${startup_args[@]+"${startup_args[@]}"})
fi
exec_args+=("${bazel_args[@]}" "$@")

cd "${repo_root}"
exec "${exec_args[@]}"
