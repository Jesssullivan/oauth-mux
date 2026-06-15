#!/usr/bin/env bash
# Download and verify the GloriousFlywheel proof artifact for oauth-mux's Zig
# REAPI candidate. Verification is delegated to GloriousFlywheel tooling.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat >&2 <<'EOF'
Usage: scripts/verify-zig-reapi-proof.sh --run-id RUN_ID [options]

Options:
  --gf-tools-dir DIR        GloriousFlywheel checkout (default: ../GloriousFlywheel)
  --workflow-repo OWNER/REPO
                            GF workflow repo (default: tinyland-inc/GloriousFlywheel)
  --run-id RUN_ID           GF REAPI Cell Proof run id
  --output-dir DIR          Artifact download directory
  --image-digest DIGEST     Require exact gf-reapi-cell digest; may use GF_REAPI_CELL_DIGEST
  --target TARGET           Required target (default: //:zig_build_test)
  --bazel-command build|test
                            Required Bazel command (default: build)
  --platform PLATFORM       Required platform (default: gloriousflywheel-rbe-linux-x86_64)
  -h, --help                Show this help

This script does not create evidence. It only downloads the GF artifact and
requires force_execution=true plus countable remote execution.
EOF
}

gf_tools_dir="${GF_REAPI_TOOLS_DIR:-${repo_root}/../GloriousFlywheel}"
workflow_repo="${GF_REAPI_WORKFLOW_REPO:-tinyland-inc/GloriousFlywheel}"
run_id=""
output_dir=""
image_digest="${GF_REAPI_CELL_DIGEST:-}"
target="//:zig_build_test"
bazel_command="build"
platform="${GF_BAZEL_REMOTE_EXECUTION_PLATFORM:-gloriousflywheel-rbe-linux-x86_64}"

while [[ $# -gt 0 ]]; do
  case "$1" in
  --gf-tools-dir)
    gf_tools_dir="${2:?missing value for --gf-tools-dir}"
    shift 2
    ;;
  --workflow-repo)
    workflow_repo="${2:?missing value for --workflow-repo}"
    shift 2
    ;;
  --run-id)
    run_id="${2:?missing value for --run-id}"
    shift 2
    ;;
  --output-dir)
    output_dir="${2:?missing value for --output-dir}"
    shift 2
    ;;
  --image-digest)
    image_digest="${2:?missing value for --image-digest}"
    shift 2
    ;;
  --target)
    target="${2:?missing value for --target}"
    shift 2
    ;;
  --bazel-command)
    bazel_command="${2:?missing value for --bazel-command}"
    shift 2
    ;;
  --platform)
    platform="${2:?missing value for --platform}"
    shift 2
    ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    echo "ERROR: unknown argument: $1" >&2
    usage
    exit 2
    ;;
  esac
done

if [[ ! ${workflow_repo} =~ ^[^/]+/[^/]+$ ]]; then
  echo "ERROR: --workflow-repo must be OWNER/REPO" >&2
  exit 2
fi

if [[ ! ${run_id} =~ ^[0-9]+$ ]]; then
  echo "ERROR: --run-id is required and must be numeric" >&2
  exit 2
fi

if [[ ! ${target} =~ ^// ]]; then
  echo "ERROR: --target must be a Bazel label beginning with //" >&2
  exit 2
fi

case "${bazel_command}" in
build | test) ;;
*)
  echo "ERROR: --bazel-command must be build or test" >&2
  exit 2
  ;;
esac

case "${platform}" in
gloriousflywheel-rbe-linux-x86_64 | gloriousflywheel-rbe-darwin-aarch64) ;;
*)
  echo "ERROR: --platform must be gloriousflywheel-rbe-linux-x86_64 or gloriousflywheel-rbe-darwin-aarch64" >&2
  exit 2
  ;;
esac

if [[ -n ${image_digest} && ! ${image_digest} =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "ERROR: --image-digest or GF_REAPI_CELL_DIGEST must be sha256:<64 lowercase hex chars>" >&2
  exit 2
fi

download_script="${gf_tools_dir}/scripts/download-gf-reapi-proof-artifact.sh"
if [[ ! -x ${download_script} ]]; then
  echo "ERROR: GloriousFlywheel verifier is required at ${download_script}" >&2
  echo "       set GF_REAPI_TOOLS_DIR to a GloriousFlywheel checkout" >&2
  exit 2
fi

args=(
  --repo "${workflow_repo}"
  --run-id "${run_id}"
  --target "${target}"
  --require-bazel-command "${bazel_command}"
  --require-force-execution
  --require-platform "${platform}"
)

if [[ -n ${output_dir} ]]; then
  args+=(--output-dir "${output_dir}")
fi

if [[ -n ${image_digest} ]]; then
  args+=(--require-image-digest "${image_digest}")
fi

exec bash "${download_script}" "${args[@]}"
