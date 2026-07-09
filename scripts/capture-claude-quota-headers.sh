#!/usr/bin/env bash
# E2 evidence harness for Claude (Anthropic) quota-signal headers.
#
# Anchor: Linear TIN-2722; docs/spec/model-quota-granularity-2026-07-03.md
#         section 5, phase P1 evidence bar; docs/runbooks/
#         claude-quota-header-capture-2026-07-10.md is the operator runbook
#         for this script.
#
# Precedent: scripts/capture-codex-wire.sh (Codex wire evidence capture).
# This script is the Claude equivalent, but there is no Claude wire proxy,
# so evidence comes from a small number of direct, operator-approved HTTP
# requests instead of passively riding mitmproxy traffic (see the runbook's
# "rejected alternatives" section for why riding CLI traffic isn't possible
# today).
#
# Honest spend ladder (TIN-2722 protocol):
#   1. no-spend channel first: an intentionally-invalid POST /v1/messages
#      (max_tokens:0, then an unknown model string) per account. Whether
#      rate-limit headers appear on a 4xx is itself a finding.
#   2. primary: micro-spend max_tokens:1 for one fable-class, one
#      opus-class, and one cheap/haiku-class model id per account.
#   3. riding CLI traffic: rejected (no proxy exists) — not implemented here.
#
# Modes:
#   --dry-run   (default) print the exact request plan per (account x model
#               x channel). Touches ~/.config/oauth-mux/config.json only;
#               NEVER touches the keychain, NEVER makes a network call.
#   --live      execute the plan for real. Reads real OAuth access tokens
#               from the macOS keychain and sends live requests to
#               https://api.anthropic.com. Refuses unless
#               OMUX_E2_OPERATOR_ACK=yes and the operator is present.
#   --redact DIR
#               transform a raw --live capture directory into a
#               committable, redacted copy. Never writes into the repo;
#               promotion into test/evidence/quota-observation/ is a manual
#               runbook step after operator review.
#
# Token handling: tokens are read from SUFFIXED keychain services only
# (never the canonical/personal service), written to a 0600 temp header
# file, and passed to curl via `-H @file`. Tokens are never placed in
# argv, never echoed, and never written into any --live output file (only
# the header file, which is shredded/removed in a trap).
#
# Accounts: xoxd, sulliwood, columbari, coye, lmux — read from
# ~/.config/oauth-mux/config.json. `personal` (the canonical, unsuffixed
# keychain service) is always excluded, defensively, even if selected via
# --account.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

ANTHROPIC_BASE="https://api.anthropic.com"
# Confirm this is still the recommended stable value during live capture.
ANTHROPIC_VERSION="2023-06-01"
CLAUDE_KEYCHAIN_SERVICE_BASE="Claude Code-credentials"
CANONICAL_ACCOUNT_NAME="personal"

# ---------------------------------------------------------------------------
# Candidate model ids for the micro-spend channel. THESE ARE PLACEHOLDERS.
# Live capture (Friday, operator present) MUST confirm/correct them before
# the resulting fixture is trusted — that correction is expected, not a
# failure. In particular "fable" has no confirmed public Anthropic model id
# anywhere in this repo (docs/spec/model-quota-granularity-2026-07-03.md
# treats "fable" as an open, discovered-not-declared #capability slug); the
# id below is a best guess and is expected to be wrong.
# ---------------------------------------------------------------------------
MODEL_ID_FABLE="claude-opus-4-5-20260101"   # UNCONFIRMED placeholder
MODEL_ID_OPUS="claude-opus-4-1-20250805"
MODEL_ID_HAIKU="claude-haiku-4-5-20251001"
UNKNOWN_MODEL_ID="claude-omux-e2-unknown-model-probe"

# Parallel arrays (bash-3.2-compatible; no associative arrays), one entry
# per request channel, in honest-spend-ladder order: no-spend first.
CHANNEL_SLUGS=(no-spend-max-tokens-0 no-spend-unknown-model micro-spend-fable micro-spend-opus micro-spend-haiku)
CHANNEL_MODELS=("$MODEL_ID_OPUS" "$UNKNOWN_MODEL_ID" "$MODEL_ID_FABLE" "$MODEL_ID_OPUS" "$MODEL_ID_HAIKU")
CHANNEL_MAXTOKENS=(0 1 1 1 1)
CHANNEL_KIND=(no-spend no-spend micro-spend micro-spend micro-spend)

MODE="dry-run"
CONFIG_PATH="${OMUX_E2_CONFIG_PATH:-$HOME/.config/oauth-mux/config.json}"
OUT_DIR_FLAG=""
REDACT_RAW_DIR=""
REDACT_OUT_FLAG=""
ACCOUNT_FILTER=()

# Set by process_account_live so the EXIT/INT/TERM trap can always clean up
# whatever header file is currently in flight, including on interruption.
CURRENT_HDR_FILE=""

usage() {
  cat <<'__USAGE_END__'
capture-claude-quota-headers.sh - TIN-2722 E2 Claude quota-header evidence capture.

USAGE
  scripts/capture-claude-quota-headers.sh [--dry-run] [OPTIONS]
  scripts/capture-claude-quota-headers.sh --live [OPTIONS]
  scripts/capture-claude-quota-headers.sh --redact RAW_DIR [--redact-out DIR]
  scripts/capture-claude-quota-headers.sh --help

MODES
  --dry-run           Default. Print the exact request plan per account x
                       channel. No keychain access, no network calls.
  --live              Execute the plan for real. Requires operator presence:
                       OMUX_E2_OPERATOR_ACK=yes must be set in the environment.
  --redact RAW_DIR     Produce a redacted, committable copy of a --live
                       output directory. Never writes inside this repo.

OPTIONS
  --config PATH        Override the oauth-mux config path
                        (default: ~/.config/oauth-mux/config.json, or
                        $OMUX_E2_CONFIG_PATH).
  --out-dir DIR         --live only: where to write the raw capture
                        (default: a fresh mktemp dir outside the repo).
  --account NAME        Restrict to one account; repeatable. Default: all
                        eligible enrolled Claude accounts except `personal`.
  --redact-out DIR       --redact only: where to write the redacted copy
                        (default: a fresh mktemp dir outside the repo, or
                        $OMUX_E2_REDACT_OUT).

ENVIRONMENT
  OMUX_E2_OPERATOR_ACK        Must be "yes" for --live to run at all.
  OMUX_E2_CONFIG_PATH         Same as --config.
  OMUX_E2_OUT_DIR              Same as --out-dir.
  OMUX_E2_REDACT_OUT           Same as --redact-out.
  OMUX_E2_ANTHROPIC_BETA       OPEN QUESTION (see runbook): if Claude Code's
                               own traffic is confirmed to send an
                               anthropic-beta header for OAuth requests, set
                               its exact value here to include it. Unset by
                               default — this script does not invent one.

See docs/runbooks/claude-quota-header-capture-2026-07-10.md for the full
operator protocol (preconditions, spend ledger, redaction review, promotion
into test/evidence/quota-observation/).
__USAGE_END__
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: missing dependency '$1': $2" >&2
    exit 64
  fi
}

utc_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

sha256_hex() {
  # sha256 hex digest of $1 (no trailing newline is fed in).
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s' "$1" | sha256sum | awk '{ print $1 }'
  else
    printf '%s' "$1" | shasum -a 256 | awk '{ print $1 }'
  fi
}

sha256_12hex() {
  # Matches src/identity_hash.zig sha256_12hex: lowercase hex of the first
  # 6 bytes of SHA-256. Golden vector: sha256_12hex("acct-test") == "660d25a9d7ee".
  sha256_hex "$1" | cut -c1-12
}

claude_keychain_service() {
  # Mirrors src/provider_schema.zig claudeKeychainService (~:744): base +
  # "-" + first 8 hex chars (first 4 bytes) of sha256(config_dir_absolute).
  # Input MUST be the tilde-expanded absolute config_dir string, not
  # realpath'd — that is the exact string Claude Code itself exports as
  # CLAUDE_CONFIG_DIR.
  local config_dir="$1"
  printf '%s-%s' "$CLAUDE_KEYCHAIN_SERVICE_BASE" "$(sha256_hex "$config_dir" | cut -c1-8)"
}

assert_path_outside_repo() {
  local path="$1" label="$2"
  mkdir -p "$path"
  local abs_path
  abs_path="$(cd "$path" && pwd -P)"
  case "$abs_path" in
    "$ROOT" | "$ROOT"/*)
      echo "error: $label resolves inside the repo worktree ($ROOT): $abs_path — refusing. Use a path outside the repo (the default, a mktemp dir, always is)." >&2
      exit 64
      ;;
  esac
}

secure_delete() {
  local f="$1"
  [[ -n "$f" && -f "$f" ]] || return 0
  if command -v shred >/dev/null 2>&1; then
    shred -u "$f" 2>/dev/null && return 0
  fi
  local sz
  sz="$(wc -c <"$f" 2>/dev/null | tr -d ' ')"
  if [[ -n "$sz" && "$sz" -gt 0 ]]; then
    dd if=/dev/urandom of="$f" bs=1 count="$sz" conv=notrunc >/dev/null 2>&1 || true
  fi
  rm -f "$f"
}

cleanup_current_hdr_file() {
  secure_delete "$CURRENT_HDR_FILE"
  CURRENT_HDR_FILE=""
}

account_selected() {
  local name="$1"
  if [[ "${#ACCOUNT_FILTER[@]}" -eq 0 ]]; then
    return 0
  fi
  local f
  for f in "${ACCOUNT_FILTER[@]}"; do
    [[ "$f" == "$name" ]] && return 0
  done
  return 1
}

# Emits one TAB-separated line per eligible Claude account:
#   name  config_dir(tilde-expanded)  keychain_service  keychain_account
# `personal` and any account that resolves to the canonical, unsuffixed
# keychain service are always excluded — never read, never printed.
list_claude_accounts() {
  python3 - "$CONFIG_PATH" "$CANONICAL_ACCOUNT_NAME" "$CLAUDE_KEYCHAIN_SERVICE_BASE" <<'PY'
import hashlib
import json
import os
import sys

config_path, canonical_name, base = sys.argv[1:]

try:
    with open(os.path.expanduser(config_path)) as f:
        cfg = json.load(f)
except FileNotFoundError:
    print(f"error: config not found: {config_path}", file=sys.stderr)
    sys.exit(64)
except json.JSONDecodeError as e:
    print(f"error: config is not valid JSON: {config_path}: {e}", file=sys.stderr)
    sys.exit(64)

claude = (cfg.get("providers") or {}).get("claude") or {}
accounts = claude.get("accounts") or {}

for name, acct in sorted(accounts.items()):
    if name == canonical_name:
        continue
    secret = acct.get("secret") or {}
    config_dir = acct.get("config_dir")
    if not config_dir:
        print(f"warning: account '{name}' has no config_dir, skipping", file=sys.stderr)
        continue
    # Tilde-expand only — NEVER realpath. Must match the exact string
    # Claude Code exports as CLAUDE_CONFIG_DIR (provider_schema.zig
    # claudeKeychainService contract).
    expanded = os.path.expanduser(config_dir)
    service = secret.get("service")
    if not service:
        digest = hashlib.sha256(expanded.encode()).hexdigest()[:8]
        service = f"{base}-{digest}"
    if service == base:
        print(f"warning: account '{name}' resolves to the canonical unsuffixed keychain service, skipping", file=sys.stderr)
        continue
    keychain_account = secret.get("account") or os.environ.get("USER", "")
    print("\t".join([name, expanded, service, keychain_account]))
PY
}

build_body() {
  local model="$1" max_tokens="$2"
  printf '{"model":"%s","max_tokens":%s,"messages":[{"role":"user","content":"omux-e2 quota-header capture probe (TIN-2722)"}]}' "$model" "$max_tokens"
}

# ---------------------------------------------------------------------------
# --dry-run
# ---------------------------------------------------------------------------

run_dry_run() {
  echo "# TIN-2722 Claude quota-header capture -- DRY RUN"
  echo "# No keychain access. No network calls. Config read only."
  echo "config_path=$CONFIG_PATH"
  echo

  local any=0
  while IFS=$'\t' read -r acct_name acct_config_dir acct_service acct_keychain_account; do
    account_selected "$acct_name" || continue
    any=1
    print_account_plan "$acct_name" "$acct_config_dir" "$acct_service" "$acct_keychain_account"
  done < <(list_claude_accounts)

  if [[ "$any" -eq 0 ]]; then
    echo "error: no eligible accounts selected (check config and --account filters)" >&2
    exit 1
  fi

  echo "# To execute for real: re-run with --live (requires OMUX_E2_OPERATOR_ACK=yes, operator present)."
}

print_account_plan() {
  local acct_name="$1" config_dir="$2" service="$3" keychain_account="$4"
  echo "== account: $acct_name =="
  echo "   config_dir:       $config_dir"
  echo "   keychain_service: $service  (derived; verify against provider_schema.zig claudeKeychainService)"
  echo "   keychain_account: $keychain_account"
  echo "   token read (NOT executed in --dry-run): security find-generic-password -s '$service' -a '$keychain_account' -w"
  echo

  local i
  for i in "${!CHANNEL_SLUGS[@]}"; do
    local slug="${CHANNEL_SLUGS[$i]}" model="${CHANNEL_MODELS[$i]}" max_tokens="${CHANNEL_MAXTOKENS[$i]}" kind="${CHANNEL_KIND[$i]}"
    local body
    body="$(build_body "$model" "$max_tokens")"
    echo "   -- channel: $slug ($kind) --"
    echo "      POST $ANTHROPIC_BASE/v1/messages"
    echo "      headers: anthropic-version: $ANTHROPIC_VERSION"
    echo "               content-type: application/json"
    echo "               authorization: Bearer <REDACTED -- read from keychain at request time; NOT read in --dry-run>"
    if [[ -n "${OMUX_E2_ANTHROPIC_BETA:-}" ]]; then
      echo "               anthropic-beta: $OMUX_E2_ANTHROPIC_BETA"
    else
      echo "               anthropic-beta: <unset -- OPEN QUESTION, see runbook; set OMUX_E2_ANTHROPIC_BETA to test a candidate value>"
    fi
    echo "      body:    $body"
    echo
  done
}

# ---------------------------------------------------------------------------
# --live
# ---------------------------------------------------------------------------

require_operator_ack() {
  if [[ "${OMUX_E2_OPERATOR_ACK:-}" != "yes" ]]; then
    cat >&2 <<'EOF'
error: --live refuses to run without explicit operator acknowledgement.

This mode reads real OAuth access tokens from the macOS keychain and sends
live requests to https://api.anthropic.com, spending a small number of
tokens per account (see docs/runbooks/claude-quota-header-capture-2026-07-10.md).

Set OMUX_E2_OPERATOR_ACK=yes only when the operator is present and has
approved the spend ladder in the runbook.
EOF
    exit 77
  fi
  if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "error: --live depends on the macOS keychain (security find-generic-password); this host is not macOS." >&2
    exit 69
  fi
}

resolve_out_dir() {
  if [[ -n "${OMUX_E2_OUT_DIR:-}" ]]; then
    printf '%s' "$OMUX_E2_OUT_DIR"
  elif [[ -n "$OUT_DIR_FLAG" ]]; then
    printf '%s' "$OUT_DIR_FLAG"
  else
    mktemp -d "${TMPDIR:-/tmp}/omux-e2-claude-quota.XXXXXX"
  fi
}

write_request_plan() {
  local plan_file="$1" url="$2" model="$3" max_tokens="$4" body="$5" beta_set="$6"
  python3 - "$plan_file" "$url" "$model" "$max_tokens" "$body" "$beta_set" <<'PY'
import json
import sys

plan_file, url, model, max_tokens, body, beta_set = sys.argv[1:]
headers = ["anthropic-version", "content-type", "authorization"]
if beta_set == "1":
    headers.append("anthropic-beta")
data = {
    "method": "POST",
    "url": url,
    "header_names": headers,
    "model": model,
    "max_tokens": int(max_tokens),
    "body": json.loads(body),
}
with open(plan_file, "w") as f:
    json.dump(data, f, indent=2, sort_keys=True)
    f.write("\n")
PY
}

write_request_meta() {
  local meta_file="$1" acct="$2" slug="$3" kind="$4" model="$5" max_tokens="$6" \
    http_code="$7" time_total="$8" ts="$9" ratelimit_present="${10}" \
    ratelimit_names="${11}" usage_tokens="${12}"
  python3 - "$meta_file" "$acct" "$slug" "$kind" "$model" "$max_tokens" \
    "$http_code" "$time_total" "$ts" "$ratelimit_present" "$ratelimit_names" "$usage_tokens" <<'PY'
import json
import sys

(meta_file, acct, slug, kind, model, max_tokens, http_code, time_total,
 ts, ratelimit_present, ratelimit_names, usage_tokens) = sys.argv[1:]
data = {
    "account": acct,
    "channel": slug,
    "kind": kind,
    "model_requested": model,
    "max_tokens_requested": int(max_tokens),
    "http_status": http_code,
    "time_total_s": time_total,
    "request_started_utc": ts,
    "ratelimit_headers_present": ratelimit_present == "true",
    "ratelimit_header_names": [n for n in ratelimit_names.split(",") if n],
    "usage_tokens": None if usage_tokens == "null" else usage_tokens,
}
with open(meta_file, "w") as f:
    json.dump(data, f, indent=2, sort_keys=True)
    f.write("\n")
PY
}

extract_usage_tokens() {
  local body_file="$1"
  python3 - "$body_file" <<'PY'
import json
import sys

try:
    with open(sys.argv[1]) as f:
        body = json.load(f)
    usage = body.get("usage") or {}
    inp = usage.get("input_tokens")
    out = usage.get("output_tokens")
    if inp is None and out is None:
        print("null")
    else:
        print(f"{inp or 0}+{out or 0}")
except Exception:
    print("null")
PY
}

run_one_request_live() {
  local acct_name="$1" acct_dir="$2" hdr_file="$3" idx="$4" ledger="$5"
  local slug="${CHANNEL_SLUGS[$idx]}" model="${CHANNEL_MODELS[$idx]}" \
    max_tokens="${CHANNEL_MAXTOKENS[$idx]}" kind="${CHANNEL_KIND[$idx]}"
  local url="$ANTHROPIC_BASE/v1/messages"
  local body
  body="$(build_body "$model" "$max_tokens")"

  local beta_set="0"
  [[ -n "${OMUX_E2_ANTHROPIC_BETA:-}" ]] && beta_set="1"

  write_request_plan "$acct_dir/$slug-request-plan.json" "$url" "$model" "$max_tokens" "$body" "$beta_set"

  local resp_headers="$acct_dir/$slug-response-headers.txt"
  local resp_body="$acct_dir/$slug-response-body.json"
  local meta_file="$acct_dir/$slug-meta.json"
  local curl_err="$acct_dir/$slug-curl-stderr.log"

  local ts_before
  ts_before="$(utc_now)"

  local curl_args=(
    -sS -X POST "$url"
    -H "anthropic-version: $ANTHROPIC_VERSION"
    -H "content-type: application/json"
    -H "@$hdr_file"
    -d "$body"
    -D "$resp_headers"
    -o "$resp_body"
    -w '%{http_code} %{time_total}'
    --max-time 30
  )
  if [[ "$beta_set" == "1" ]]; then
    curl_args+=(-H "anthropic-beta: $OMUX_E2_ANTHROPIC_BETA")
  fi

  local curl_out http_code time_total
  curl_out="$(curl "${curl_args[@]}" 2>"$curl_err")" || curl_out=""
  if [[ -z "$curl_out" ]]; then
    http_code="ERR"
    time_total="0"
  else
    http_code="$(awk '{print $1}' <<<"$curl_out")"
    time_total="$(awk '{print $2}' <<<"$curl_out")"
  fi

  local ratelimit_present="false" ratelimit_names=""
  if [[ -f "$resp_headers" ]] && grep -qi 'ratelimit' "$resp_headers" 2>/dev/null; then
    ratelimit_present="true"
    ratelimit_names="$(grep -io '^[a-z0-9-]*ratelimit[a-z0-9-]*' "$resp_headers" 2>/dev/null | tr '\n' ',' | sed 's/,$//')"
  fi

  local usage_tokens="null"
  [[ -f "$resp_body" ]] && usage_tokens="$(extract_usage_tokens "$resp_body")"

  write_request_meta "$meta_file" "$acct_name" "$slug" "$kind" "$model" "$max_tokens" \
    "$http_code" "$time_total" "$ts_before" "$ratelimit_present" "$ratelimit_names" "$usage_tokens"

  printf '%-10s %-24s %-40s %-6s %-4s %-16s %-8s\n' \
    "$acct_name" "$slug" "$model" "$http_code" "$max_tokens" "$usage_tokens" "$ratelimit_present" >>"$ledger"

  echo "captured: account=$acct_name channel=$slug http=$http_code ratelimit_headers=$ratelimit_present"
}

process_account_live() {
  local acct_name="$1" service="$2" keychain_account="$3" out_dir="$4" ledger="$5"
  local acct_dir="$out_dir/$acct_name"
  mkdir -p "$acct_dir"

  local hdr_file
  hdr_file="$(mktemp "${TMPDIR:-/tmp}/omux-e2-hdr.XXXXXX")"
  chmod 600 "$hdr_file"
  CURRENT_HDR_FILE="$hdr_file"

  local token
  if ! token="$(security find-generic-password -s "$service" -a "$keychain_account" -w 2>/dev/null)"; then
    echo "warning: could not read keychain item for account '$acct_name' (service=$service, account=$keychain_account); skipping" >&2
    cleanup_current_hdr_file
    return 0
  fi
  printf 'Authorization: Bearer %s\n' "$token" >"$hdr_file"
  token=""

  local i
  for i in "${!CHANNEL_SLUGS[@]}"; do
    run_one_request_live "$acct_name" "$acct_dir" "$hdr_file" "$i" "$ledger"
  done

  cleanup_current_hdr_file
}

run_live_capture() {
  require_cmd curl "install curl"
  require_cmd security "macOS only: 'security' ships with the OS"
  require_operator_ack

  local out_dir
  out_dir="$(resolve_out_dir)"
  assert_path_outside_repo "$out_dir" "--live output directory"

  trap cleanup_current_hdr_file EXIT INT TERM

  local ledger="$out_dir/SPEND-LEDGER.txt"
  {
    printf 'TIN-2722 Claude quota-header capture -- spend ledger\n'
    printf 'run_started_utc=%s\n' "$(utc_now)"
    printf 'config_path=%s\n' "$CONFIG_PATH"
    printf '\n'
    printf '%-10s %-24s %-40s %-6s %-4s %-16s %-8s\n' account channel model http_status max_tokens usage_tokens ratelimit_hdrs
  } >"$ledger"

  local any=0
  while IFS=$'\t' read -r acct_name acct_config_dir acct_service acct_keychain_account; do
    account_selected "$acct_name" || continue
    any=1
    process_account_live "$acct_name" "$acct_service" "$acct_keychain_account" "$out_dir" "$ledger"
  done < <(list_claude_accounts)

  if [[ "$any" -eq 0 ]]; then
    echo "error: no eligible accounts selected (check config and --account filters)" >&2
    exit 1
  fi

  echo
  echo "live capture complete: $out_dir"
  echo "next: $0 --redact '$out_dir'"
}

# ---------------------------------------------------------------------------
# --redact
# ---------------------------------------------------------------------------

run_redact() {
  local raw_dir="$1"
  require_cmd python3 "install python3"
  [[ -d "$raw_dir" ]] || { echo "error: raw capture dir not found: $raw_dir" >&2; exit 64; }

  local redact_out
  if [[ -n "$REDACT_OUT_FLAG" ]]; then
    redact_out="$REDACT_OUT_FLAG"
  elif [[ -n "${OMUX_E2_REDACT_OUT:-}" ]]; then
    redact_out="$OMUX_E2_REDACT_OUT"
  else
    redact_out="$(mktemp -d "${TMPDIR:-/tmp}/omux-e2-redacted.XXXXXX")"
  fi
  assert_path_outside_repo "$redact_out" "--redact output directory"

  python3 - "$raw_dir" "$redact_out" <<'PY'
import hashlib
import json
import os
import re
import sys
from pathlib import Path

raw_dir = Path(sys.argv[1])
out_dir = Path(sys.argv[2])

# Mirrors src/fixture_redaction.zig forbidden_markers. Keep the two lists in
# sync by hand; this is a pre-commit safety net for --redact output, not the
# authoritative gate -- that is `just test-local` (fixture_redaction) plus
# gitleaks, both required by the runbook before any commit.
FORBIDDEN_MARKERS = [
    "access_token", "refresh_token", "id_token", "client_secret",
    "authorization:", "authorization=", "bearer ", "bearer%20",
    "set-cookie:", "cookie:", "sk-", "sess-",
]

# Headers dropped entirely rather than redacted-in-place. authorization is
# the obvious one; www-authenticate/proxy-authenticate commonly echo the
# literal word "Bearer" in a 401 challenge (e.g. `Bearer realm="..."`),
# which would otherwise trip the "bearer " forbidden marker above for no
# evidentiary value -- neither header carries quota/ratelimit signal.
STRIP_HEADERS = {"authorization", "www-authenticate", "proxy-authenticate"}

ID_LIKE_KEYS = {
    "id", "request_id", "request-id", "x-request-id", "organization_id",
    "org_id", "account_id", "user_id", "session_id",
    "anthropic-organization-id", "anthropic-request-id", "cf-ray",
}


def sha256_12hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def is_id_like(key: str) -> bool:
    low = key.lower()
    return low in ID_LIKE_KEYS or low.endswith("_id") or low.endswith("-id")


def redact_headers_text(text: str) -> str:
    out_lines = []
    for line in text.splitlines():
        if not line.strip() or ":" not in line:
            out_lines.append(line)
            continue
        name, _, value = line.partition(":")
        key = name.strip().lower()
        if key in STRIP_HEADERS:
            continue
        value = value.strip()
        if is_id_like(key):
            value = f"<{sha256_12hex(value)}>"
        out_lines.append(f"{name.strip()}: {value}")
    return "\n".join(out_lines) + ("\n" if text.endswith("\n") else "")


def redact_json_value(key, value):
    if isinstance(value, dict):
        return {k: redact_json_value(k, v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_json_value(key, v) for v in value]
    if isinstance(value, str):
        if isinstance(key, str) and is_id_like(key):
            return f"<{sha256_12hex(value)}>"
        return value
    return value  # numbers/bools/null kept verbatim -- these are the signal.


def redact_json_body(text: str) -> str:
    try:
        data = json.loads(text)
    except Exception:
        return text  # not JSON; pass through, still subject to the marker self-check below.
    return json.dumps(redact_json_value(None, data), indent=2, sort_keys=True) + "\n"


violations = []
for root, _dirs, files in os.walk(raw_dir):
    rel_root = Path(root).relative_to(raw_dir)
    parts = list(rel_root.parts)
    if parts:
        parts[0] = sha256_12hex(parts[0])  # hash the account label
    dest_root = out_dir.joinpath(*parts) if parts else out_dir
    dest_root.mkdir(parents=True, exist_ok=True)

    for fname in files:
        src = Path(root) / fname
        dest = dest_root / fname
        text = src.read_text(errors="replace")
        if fname.endswith("headers.txt"):
            redacted = redact_headers_text(text)
        elif fname.endswith(".json"):
            redacted = redact_json_body(text)
        else:
            redacted = text  # SPEND-LEDGER.txt / curl-stderr.log: header names + numeric values by construction.
        dest.write_text(redacted)

        low = redacted.lower()
        for marker in FORBIDDEN_MARKERS:
            if marker in low:
                violations.append(f"{dest}: forbidden marker '{marker}'")

if violations:
    sys.stderr.write("redact: FAILED self-check -- forbidden markers survived redaction:\n")
    for v in violations:
        sys.stderr.write(f"  - {v}\n")
    sys.stderr.write("Fix the redaction logic or hand-review these files before promotion. Nothing here should be committed as-is.\n")
    sys.exit(1)

print(f"redact: wrote {out_dir}")
print("redact: self-check passed (no forbidden markers found)")
print("next: manual review, then gitleaks + `just test-local` (fixture_redaction), then promote into")
print("      test/evidence/quota-observation/claude-<UTCts>/ per the runbook.")
PY

  echo "redacted output: $redact_out"
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      MODE="dry-run"
      shift
      ;;
    --live)
      MODE="live"
      shift
      ;;
    --redact)
      MODE="redact"
      shift
      [[ $# -gt 0 ]] || { echo "error: --redact requires a raw capture directory" >&2; exit 64; }
      REDACT_RAW_DIR="$1"
      shift
      ;;
    --redact-out)
      shift
      [[ $# -gt 0 ]] || { echo "error: --redact-out requires a path" >&2; exit 64; }
      REDACT_OUT_FLAG="$1"
      shift
      ;;
    --config)
      shift
      [[ $# -gt 0 ]] || { echo "error: --config requires a path" >&2; exit 64; }
      CONFIG_PATH="$1"
      shift
      ;;
    --out-dir)
      shift
      [[ $# -gt 0 ]] || { echo "error: --out-dir requires a path" >&2; exit 64; }
      OUT_DIR_FLAG="$1"
      shift
      ;;
    --account)
      shift
      [[ $# -gt 0 ]] || { echo "error: --account requires a name" >&2; exit 64; }
      ACCOUNT_FILTER+=("$1")
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage
      exit 64
      ;;
  esac
done

require_cmd python3 "install python3"

case "$MODE" in
  dry-run) run_dry_run ;;
  live) run_live_capture ;;
  redact)
    [[ -n "$REDACT_RAW_DIR" ]] || { echo "error: --redact requires a raw capture directory" >&2; exit 64; }
    run_redact "$REDACT_RAW_DIR"
    ;;
  *)
    echo "error: unknown mode: $MODE" >&2
    exit 70
    ;;
esac
