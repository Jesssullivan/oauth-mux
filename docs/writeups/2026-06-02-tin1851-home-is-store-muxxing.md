# TIN-1851: home-is-store Codex muxxing (the real fix)

**Status:** implemented on `tin-1851-codex-muxxing-fix`. Default behavior change.

## Problem

The previous default muxxed a Codex session through a *canonical bridge* overlay:
a throwaway `CODEX_HOME` whose `sessions/` and `state_5.sqlite` were symlinked to the
canonical `~/.codex`, with child `CODEX_SQLITE_HOME` pointed at the canonical store.
Codex recorded the ephemeral overlay's `rollout_path`s into the **shared canonical**
`state_5.sqlite`; when the overlay (or `$TMPDIR`) was reaped those rows dangled. This
corrupted the user's real `~/.codex` for ~3 weeks and broke even bare, non-muxxed
Codex sessions. (See the codex-muxxing temp-home poisoning notes and `bde09d72`, which
decoupled muxxing to opt-in as a stopgap.)

## Model B: home-is-store (default `isolated_persistent`)

Each muxxed account already enrolls with a dedicated per-account home, e.g.

```json
"max-1": {
  "config_dir": "~/.local/share/oauth-mux/codex/max-1",
  "secret": { "backend": "file", "path": "~/.local/share/oauth-mux/codex/max-1/auth.json" }
}
```

The fix uses that home **directly** as `CODEX_HOME`:

- `CODEX_HOME = dirname(source_auth_path)` — guaranteed equal to the exact `auth.json`
  the refresh/identity locks key on, and the file codex reads at `$CODEX_HOME/auth.json`.
- **No auth copy**: codex refreshes `auth.json` in place; there is no overlay buffer to
  diverge or lose a rotated refresh token from.
- **No canonical bridge**: `sqlite_authority = isolated_overlay`, `CODEX_SQLITE_HOME` is
  removed, so codex writes its **own** `state_5.sqlite` and `sessions/` inside the home.
  The canonical `~/.codex` is never a write target → the poisoning vector is *structurally*
  gone, and distinct accounts get fully disjoint stores (the product goal: concurrent use
  of distinct $200 accounts).
- **Persistent**: the home is durable, so native `codex resume` works without symlink
  bridging or `CODEX_SQLITE_HOME` juggling.

The legacy bridge stays available, strictly opt-in, via `TINYLAND_CODEX_MUX_MODE=shared_canonical`
(or `--mux-mode shared_canonical`). `--session-home` and `--isolated-session-store` keep their
existing meanings.

## Guard set (load-bearing — naive home-is-store is unsafe without these)

1. **Canonical-overlap refuse** (`ensureNotCanonicalCodexHome`): fatal if the resolved
   `CODEX_HOME` (lexically or symlink-resolved) is, contains, or is contained by `~/.codex`.
   Prevents a misconfigured `secret.path`/`config_dir` from writing managed config + state
   into the real store.
2. **Home derived from the auth file** + basename must be `auth.json`; refuse a home with no
   usable `auth.json` rather than silently bootstrapping an empty/unauthenticated home.
3. **Fresh config, scrubbed on exit**: the managed `config.toml` is written fresh each launch
   (no passthrough self-read) carrying only the proxy override; on clean exit it is deleted
   (`persist_scrub_config`) so a dead ephemeral proxy port can never brick a later bare-codex
   run, and the home is not misclassified as a managed overlay next launch.
4. **Per-account + identity session flock** (landed in the 2c increment): the session holds
   `acquireRepairLockBlocking("codex", account)` — the *same* lock domain as background
   refresh — plus a `sha256_12hex(account_id)` identity flock, for the whole session. Same
   account or shared upstream identity cannot run concurrently and self-revoke the rotating
   refresh chain.
5. **Auth integrity preflight + shadow backup** (`auth.json.omux-bak`): recover a torn in-place
   write / crash-mid-refresh; refuse if neither the live file nor the shadow is usable.

## Verification

Unit tests cover the dispatch, the overlap guard, the config/shadow scrub, and crash recovery.
Per the unit-green≠working lesson, the gate is the **live** `scripts/live-codex-mux-e2e.sh`
(driven against `jess@xoxd.ai`): a real managed `codex exec` returns the token, **0** new
`oauth-mux-codex`/`omux-managed` rows appear in canonical `~/.codex/state_5.sqlite`, integrity
stays `ok`, no token/config material leaks under `~/.codex/.oauth-mux`, and `session_authority`
is `isolated`. Follow-up: bounded `sessions/` retention sweep; config-validation home-uniqueness.
