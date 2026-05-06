# oauth-mux

`oauth-mux` is an OAuth/account broker for developer harnesses. The product
target is:

> The user runs `oauth-mux <harness>` such as `oauth-mux codex`. The harness
> behaves like the real one. The active subscription account exhausts quota.
> Another credited account is substituted in place. The harness process is not
> restarted. The user is not prompted.

Restart, supervised relaunch, route-warming, and `prepared_fallback` are not
product success. They are diagnostics or lower-level infrastructure.

## Current Codex State

Real on `main`:

- Broker MCP/account selection core exists.
- `oauth-mux codex` runs Codex in a managed frame with mux-owned auth/config
  and a canonical Codex session-authority bridge.
- Brokered Codex resume has been dogfooded successfully through the proxy:
  `resume <session-id>` reached `POST /backend-api/codex/responses` with
  `status:200`.
- Current dogfood status evidence includes hundreds of brokered
  `POST /responses` 200s through `codex:max-1`; it does not yet include a real
  provider-originated `429 usage_limit_reached` or fallback-account turn.
- Synthetic smokes prove account A can hit `429 usage_limit_reached`, be
  marked exhausted, and account B can handle the same request in the same child
  process before Codex receives the 429.
- Same-account Codex child refresh is preserved so oauth-mux does not pin Codex
  to stale materialized access tokens after a native refresh.

Not proven yet:

- Live provider-originated account exhaustion inside a managed `oauth-mux codex`
  session.
- Live invisible same-turn recovery where Codex never sees the quota failure.
- Same-thread continuity across account swap.
- Bare `codex` plus a separate background oauth-mux daemon seamlessly handing
  off accounts.
- Claude, Cursor, Pi, or other harness adapters.

The current Codex proxy implementation now has a synthetic same-turn retry path:
it classifies `429 usage_limit_reached`, marks the active account exhausted,
elects a fallback account, drops `x-codex-turn-state`, and retries the same
request before writing the response to Codex. That is still not a live product
claim until real provider-originated quota exhaustion proves the same sequence.

## Truth Sources

- `AGENTS.md`
- `docs/spec/broker-mcp-contract-2026-05-03.md`
- `docs/spec/codex-adapter-contract-2026-05-03.md`
- `docs/spec/harness-session-authority-bridge-2026-05-05.md`
- `docs/spec/codex-managed-resume-ux-refactor-2026-05-06.md`
- `docs/spec/test-and-coverage-review-2026-05-05.md`
- `docs/spec/broker-worktree-quarry-todo-2026-05-05.md`

## Testing Ladder

Use `just` as the entrypoint.

```bash
just build
just test
just check-local
```

The evidence ladder is:

- Unit tests and deterministic PBT-style tests in Zig for parsers, route state,
  classification, session ids, credential handles, header copying, and overlay
  invariants.
- Shell e2e/smoke tests for broker MCP, Codex CLI UX, Codex synthetic swap,
  concurrent sessions, same-account child refresh, tier-insufficient handling,
  all-accounts-exhausted handling, 401 propagation, and cassette replay.
- Cassette replay infrastructure for scrubbed Codex wire captures.
- Live QA only after local and cassette layers are green, with explicit spend
  consent and redacted status artifacts.

Next P0: capture and run live evidence for provider-originated
`429 usage_limit_reached` inside a managed session. Until that proves the same
no-visible-429 sequence against real `chatgpt.com`, live quota-burn dogfood is
telemetry, not product acceptance.

Summarize a dogfood status artifact without overclaiming:

```bash
python3 scripts/summarize-codex-status.py dist/live-qa/<run>/status.ndjson --require-brokered
```

`verdict:"brokered_without_fallback"` means the session went through oauth-mux
but did not observe account exhaustion or substitution. The Level 3/4 evidence
shape requires a `quota_exhausted` proxy turn, a retry/swap event, and a
successful turn on a distinct fallback account.
`verdict:"brokered_auth_failed"` means the managed frame started, but upstream
returned unrecovered `401 auth_unauthorized` responses. That is an auth-health
failure, not quota fallback evidence.
