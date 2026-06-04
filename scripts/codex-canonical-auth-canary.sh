#!/usr/bin/env bash
# codex-canonical-auth-canary: regression guard for the system-wide Codex auth
# poisoning that killed the dev accounts (2026-05/06). Asserts the four invariants
# that must hold for canonical ~/.codex to stay working. Exits non-zero on any
# violation so it can gate a switch, a cron alert, or a pre-flight check.
#
# It NEVER prints token/credential contents — only presence/shape and markers.
#
#   1. ~/.codex/auth.json exists and parses (codex login wrote a real credential).
#   2. ~/.codex/.oauth-mux does NOT exist (oauth-mux canonical-bridge muxxing has
#      not run against the real home — that bridge is what recorded/scrubbed state
#      into ~/.codex and is the poisoning vector).
#   3. The sops-nix codex/auth blob stays renamed/absent, so a home-manager switch
#      cannot re-materialize a stale auth.json over the live rotated tokens
#      (the 995b72d8 vector). Rotating OAuth tokens must never live in sops.
#   4. ~/.codex/config.toml carries no oauth-mux proxy override (a dead 127.0.0.1
#      port left in the canonical config bricks native codex).

set -uo pipefail

CODEX_HOME_DIR="${CODEX_HOME:-$HOME/.codex}"
LAB_SOPS_BLOB="${OMUX_LAB_SOPS_CODEX_BLOB:-$HOME/git/lab/nix/secrets/codex/auth.json}"
fail=0

check() { # name, ok(0/1), detail
  if [ "$2" = "0" ]; then
    printf 'PASS  %-34s %s\n' "$1" "${3:-}"
  else
    printf 'FAIL  %-34s %s\n' "$1" "${3:-}"
    fail=1
  fi
}

# 1. canonical auth.json present + parses
auth="$CODEX_HOME_DIR/auth.json"
if [ -f "$auth" ] && python3 -c "import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if isinstance(d,dict) and d.get('tokens') else 1)" "$auth" 2>/dev/null; then
  check "canonical_auth_present" 0 "$auth ok"
else
  check "canonical_auth_present" 1 "$auth MISSING or unparseable -> run: codex login"
fi

# 2. no oauth-mux bridge target inside the canonical home
if [ -e "$CODEX_HOME_DIR/.oauth-mux" ]; then
  check "no_canonical_bridge_residue" 1 "$CODEX_HOME_DIR/.oauth-mux exists -> muxxing ran against canonical; quarantine it"
else
  check "no_canonical_bridge_residue" 0 "no $CODEX_HOME_DIR/.oauth-mux"
fi

# 3. sops codex/auth materialization stays disabled (blob absent at the gated path)
if [ -e "$LAB_SOPS_BLOB" ]; then
  check "sops_codex_auth_disabled" 1 "$LAB_SOPS_BLOB present -> sops will clobber ~/.codex/auth.json on switch; keep it renamed/.DISABLED"
else
  check "sops_codex_auth_disabled" 0 "sops codex/auth blob absent (gate off)"
fi

# 4. canonical config.toml has no dead proxy override
cfg="$CODEX_HOME_DIR/config.toml"
if [ -f "$cfg" ] && grep -qE 'Managed by oauth-mux|oauth_mux_openai|127\.0\.0\.1.*backend-api' "$cfg" 2>/dev/null; then
  check "config_no_proxy_poison" 1 "$cfg carries an oauth-mux proxy override -> native codex routes to a dead port"
else
  check "config_no_proxy_poison" 0 "$cfg clean"
fi

echo
if [ "$fail" = "0" ]; then
  echo "codex-canonical-auth-canary: OK (canonical ~/.codex auth invariants hold)"
else
  echo "codex-canonical-auth-canary: REGRESSION DETECTED (see FAILs above)" >&2
fi
exit "$fail"
