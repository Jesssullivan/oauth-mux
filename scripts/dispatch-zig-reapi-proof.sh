#!/usr/bin/env bash
# Dispatch oauth-mux's bounded Zig target to GloriousFlywheel's explicit REAPI
# proof workflow. This script does not run Bazel locally and does not itself
# prove RBE; the GF proof artifact/verifier remains the authority.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat >&2 <<'EOF'
Usage: scripts/dispatch-zig-reapi-proof.sh --image-digest sha256:<64 hex> [options]

Options:
  --workflow-repo OWNER/REPO          GF workflow repo (default: tinyland-inc/GloriousFlywheel)
  --workflow-ref REF                  GF workflow ref (default: main)
  --request-id ID                     Correlation id; default tin2105-oauth-mux-zig-<time>-<sha>
  --image-digest DIGEST               Published gf-reapi-cell image digest; may use GF_REAPI_CELL_DIGEST
  --target TARGET                     Bazel target to prove (default: //:zig_build_test)
  --bazel-command build|test          Bazel command (default: build)
  --platform PLATFORM                 GF platform (default: gloriousflywheel-rbe-linux-x86_64)
  --remote-executor ENDPOINT          Optional explicit grpc(s):// executor
  --consumer-repository OWNER/REPO    Consumer repo (default: Jesssullivan/oauth-mux)
  --consumer-ref REF                  Consumer ref; default current branch or HEAD sha
  --consumer-checkout-authority AUTH  github-app, owner-scoped-secret, repo-scoped-deploy-key
  --require-consumer-app-token        Require GF GitHub App checkout auth
  --skip-apply                        Do not scale/apply the Linux gf-reapi-cell proof endpoint
  --scale-to-zero-after-proof         Ask GF to scale the endpoint down after proof
  --no-force-execution                Allow cache-hit-only runs; not acceptable for TIN-2105 proof
  --dry-run                           Print the gh workflow command only
  -h, --help                          Show this help

Countable TIN-2105 proof still requires the GF artifact verifier to pass with
force_execution=true, remote_processes > 0, worker image digest, and no local
fallback.
EOF
}

current_ref() {
  local branch
  branch="$(git -C "${repo_root}" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
  if [[ -n ${branch} && ${branch} != "HEAD" ]]; then
    printf '%s\n' "${branch}"
    return
  fi
  git -C "${repo_root}" rev-parse HEAD
}

workflow_repo="${GF_REAPI_WORKFLOW_REPO:-tinyland-inc/GloriousFlywheel}"
workflow_ref="${GF_REAPI_WORKFLOW_REF:-main}"
request_id=""
image_digest="${GF_REAPI_CELL_DIGEST:-}"
target="//:zig_build_test"
bazel_command="build"
platform="${GF_BAZEL_REMOTE_EXECUTION_PLATFORM:-gloriousflywheel-rbe-linux-x86_64}"
remote_executor="${BAZEL_REMOTE_EXECUTOR:-}"
consumer_repository="${GF_REAPI_CONSUMER_REPOSITORY:-Jesssullivan/oauth-mux}"
consumer_ref="${GF_REAPI_CONSUMER_REF:-}"
consumer_checkout_authority="${GF_REAPI_CONSUMER_CHECKOUT_AUTHORITY:-github-app}"
require_consumer_app_token="false"
apply="true"
scale_to_zero_after_proof="false"
force_execution="true"
dry_run="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
  --workflow-repo)
    workflow_repo="${2:?missing value for --workflow-repo}"
    shift 2
    ;;
  --workflow-ref)
    workflow_ref="${2:?missing value for --workflow-ref}"
    shift 2
    ;;
  --request-id)
    request_id="${2:?missing value for --request-id}"
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
  --remote-executor)
    remote_executor="${2:?missing value for --remote-executor}"
    shift 2
    ;;
  --consumer-repository)
    consumer_repository="${2:?missing value for --consumer-repository}"
    shift 2
    ;;
  --consumer-ref)
    consumer_ref="${2:?missing value for --consumer-ref}"
    shift 2
    ;;
  --consumer-checkout-authority)
    consumer_checkout_authority="${2:?missing value for --consumer-checkout-authority}"
    shift 2
    ;;
  --require-consumer-app-token)
    require_consumer_app_token="true"
    shift
    ;;
  --skip-apply)
    apply="false"
    shift
    ;;
  --scale-to-zero-after-proof)
    scale_to_zero_after_proof="true"
    shift
    ;;
  --no-force-execution)
    force_execution="false"
    shift
    ;;
  --dry-run)
    dry_run="true"
    shift
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

if [[ -z ${consumer_ref} ]]; then
  consumer_ref="$(current_ref)"
fi

if [[ -z ${request_id} ]]; then
  request_id="tin2105-oauth-mux-zig-$(date -u +%Y%m%dT%H%M%SZ)-$(git -C "${repo_root}" rev-parse --short HEAD)"
fi

if [[ ! ${workflow_repo} =~ ^[^/]+/[^/]+$ ]]; then
  echo "ERROR: --workflow-repo must be OWNER/REPO" >&2
  exit 2
fi

if [[ ! ${consumer_repository} =~ ^[^/]+/[^/]+$ ]]; then
  echo "ERROR: --consumer-repository must be OWNER/REPO" >&2
  exit 2
fi

if [[ -z ${workflow_ref} || -z ${consumer_ref} ]]; then
  echo "ERROR: workflow and consumer refs must be non-empty" >&2
  exit 2
fi

if [[ ! ${request_id} =~ ^[A-Za-z0-9._:-]+$ ]]; then
  echo "ERROR: --request-id may contain only letters, numbers, dot, underscore, colon, or dash" >&2
  exit 2
fi

if [[ ! ${image_digest} =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "ERROR: --image-digest or GF_REAPI_CELL_DIGEST must be sha256:<64 lowercase hex chars>" >&2
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

case "${consumer_checkout_authority}" in
github-app | owner-scoped-secret | repo-scoped-deploy-key) ;;
*)
  echo "ERROR: --consumer-checkout-authority must be github-app, owner-scoped-secret, or repo-scoped-deploy-key" >&2
  exit 2
  ;;
esac

if [[ -n ${remote_executor} && ! ${remote_executor} =~ ^(grpc|grpcs):// ]]; then
  echo "ERROR: --remote-executor must start with grpc:// or grpcs://" >&2
  exit 2
fi

linux_executor="grpc://gf-reapi-cell.gf-rbe.svc.cluster.local:8980"
if [[ ${platform} == "gloriousflywheel-rbe-darwin-aarch64" ]]; then
  if [[ -z ${remote_executor} ]]; then
    echo "ERROR: Darwin platform requires --remote-executor" >&2
    exit 2
  fi
  if [[ ${remote_executor} == "${linux_executor}" ]]; then
    echo "ERROR: Darwin platform cannot use the Linux gf-reapi-cell executor" >&2
    exit 2
  fi
  if [[ ${apply} == "true" ]]; then
    echo "ERROR: Darwin platform requires --skip-apply" >&2
    exit 2
  fi
fi

case "${apply}" in true | false) ;;
*) echo "ERROR: apply must be true or false" >&2; exit 2 ;;
esac
case "${scale_to_zero_after_proof}" in true | false) ;;
*) echo "ERROR: scale_to_zero_after_proof must be true or false" >&2; exit 2 ;;
esac
case "${force_execution}" in true | false) ;;
*) echo "ERROR: force_execution must be true or false" >&2; exit 2 ;;
esac

cmd=(
  gh workflow run gf-reapi-cell-proof.yml
  --repo "${workflow_repo}"
  --ref "${workflow_ref}"
  -f "request_id=${request_id}"
  -f "image_digest=${image_digest}"
  -f "target=${target}"
  -f "bazel_command=${bazel_command}"
  -f "platform=${platform}"
  -f "remote_executor=${remote_executor}"
  -f "workspace_path=consumer-workspace"
  -f "consumer_repository=${consumer_repository}"
  -f "consumer_ref=${consumer_ref}"
  -f "require_consumer_app_token=${require_consumer_app_token}"
  -f "consumer_checkout_authority=${consumer_checkout_authority}"
  -f "was110_public_handoff=false"
  -f "tinyland_schemas_private_handoff=false"
  -f "apply=${apply}"
  -f "scale_to_zero_after_proof=${scale_to_zero_after_proof}"
  -f "force_execution=${force_execution}"
)

if [[ ${dry_run} == "true" ]]; then
  printf '%q ' "${cmd[@]}"
  printf '\n'
  exit 0
fi

if [[ ${force_execution} != "true" ]]; then
  echo "WARN: --no-force-execution runs are not countable TIN-2105 proof." >&2
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "ERROR: gh is required to dispatch GF REAPI Cell Proof" >&2
  exit 127
fi

printf 'Dispatching GF REAPI proof request_id=%s consumer_ref=%s target=%s\n' \
  "${request_id}" "${consumer_ref}" "${target}" >&2
printf 'After dispatch, find the run with:\n' >&2
printf '  gh run list --repo %q --workflow gf-reapi-cell-proof.yml --json databaseId,displayTitle,status,conclusion,url --jq %q\n' \
  "${workflow_repo}" ".[] | select(.displayTitle | contains(\"${request_id}\"))" >&2

exec "${cmd[@]}"
