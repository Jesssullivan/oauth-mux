#!/usr/bin/env bash
# Post a GitHub tracker comment through local gh when the Apps connector is
# read-only or missing issue-comment permission.

set -euo pipefail

repo="${OMUX_GITHUB_REPO:-Jesssullivan/oauth-mux}"
dry_run=false
ignore_env_token=false

usage() {
  cat <<'OMUX_GH_COMMENT_USAGE'
github-tracker-comment.sh - guarded local-gh fallback for tracker comments

USAGE
  scripts/github-tracker-comment.sh [--repo OWNER/REPO] [--dry-run] [--ignore-env-token] ISSUE BODY_FILE
  scripts/github-tracker-comment.sh [--repo OWNER/REPO] [--dry-run] ISSUE -

OPTIONS
  --repo OWNER/REPO      GitHub repository. Defaults to OMUX_GITHUB_REPO or Jesssullivan/oauth-mux.
  --dry-run              Validate the body and auth surface without posting.
  --ignore-env-token     Unset GH_TOKEN/GITHUB_TOKEN so gh falls back to keyring auth.

SAFETY
  The body is scanned for obvious bearer/JWT/API-key/PAT-shaped secrets before
  posting. This is a high-signal guard, not a proof of full redaction.
OMUX_GH_COMMENT_USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      repo="${2:-}"
      if [[ -z "$repo" ]]; then
        echo "error: --repo requires OWNER/REPO" >&2
        exit 64
      fi
      shift 2
      ;;
    --dry-run)
      dry_run=true
      shift
      ;;
    --ignore-env-token)
      ignore_env_token=true
      shift
      ;;
    -h|--help|help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 64
      ;;
    *)
      break
      ;;
  esac
done

if [[ $# -ne 2 ]]; then
  usage >&2
  exit 64
fi

issue="$1"
body_arg="$2"

if ! [[ "$issue" =~ ^[0-9]+$ ]]; then
  echo "error: ISSUE must be a numeric issue or PR number" >&2
  exit 64
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "error: gh is required for tracker comment fallback" >&2
  exit 64
fi

tmp_body=""
cleanup() {
  if [[ -n "$tmp_body" ]]; then
    rm -f "$tmp_body"
  fi
}
trap cleanup EXIT

if [[ "$body_arg" == "-" ]]; then
  tmp_body="$(mktemp -t omux-gh-comment.XXXXXX)"
  cat >"$tmp_body"
  body_file="$tmp_body"
else
  body_file="$body_arg"
fi

if [[ ! -f "$body_file" ]]; then
  echo "error: body file does not exist: $body_file" >&2
  exit 66
fi

if [[ ! -s "$body_file" ]]; then
  echo "error: body file is empty" >&2
  exit 65
fi

if grep -Eiq \
  '(Bearer[[:space:]]+[A-Za-z0-9._~+/=-]{20,}|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}|sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{20,})' \
  "$body_file"; then
  echo "error: body contains a possible unredacted secret; refusing to post" >&2
  exit 65
fi

if [[ "$ignore_env_token" == true ]]; then
  unset GH_TOKEN GITHUB_TOKEN
fi

if [[ "$dry_run" == true ]]; then
  gh auth status --hostname github.com >/dev/null
  printf 'github-tracker-comment: dry-run ok repo=%s issue=%s body_file=%s\n' "$repo" "$issue" "$body_file"
  exit 0
fi

gh issue comment "$issue" --repo "$repo" --body-file "$body_file"
