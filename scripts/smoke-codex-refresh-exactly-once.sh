#!/usr/bin/env bash
# Exactly-once refresh race smoke (TIN-1785 acceptance).
#
# N concurrent `oauth-mux mcp` processes materialize one stale codex account
# against a local stub token endpoint. The per-provider:account blocking flock
# on the refresh write path + the under-lock freshness re-read must collapse
# the race into exactly ONE refresh POST, zero refresh-token replays, and a
# store that ends on the rotated chain. Against a no-lock write path (the
# pre-PR-#351 shape) this fails: every racer replays the single-use refresh
# token and the stub answers invalid_grant — the codex-refresh-token-race
# incident (GH #336 / PR #337).
#
# No provider traffic is made; the token endpoint is a local stub.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/zig-out/bin/oauth-mux"

if [[ ! -x "$BIN" ]]; then
    echo "smoke-codex-refresh-exactly-once: oauth-mux binary not built at $BIN" >&2
    echo "  run: just build-local" >&2
    exit 64
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "smoke-codex-refresh-exactly-once: python3 required" >&2
    exit 64
fi

echo "smoke-codex-refresh-exactly-once: 4 racers, one account, one stub token endpoint"
python3 "$ROOT/scripts/test-refresh-exactly-once.py" --bin "$BIN" --racers 4
echo "smoke-codex-refresh-exactly-once: PASS"
