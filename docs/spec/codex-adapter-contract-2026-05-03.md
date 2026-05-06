# Codex Adapter Contract
Date: 2026-05-03
Status: load-bearing. This is the per-harness adapter spec for Codex.
Anchor: `docs/spec/broker-mcp-contract-2026-05-03.md` (the broker is the
truth source; this spec describes how the Codex adapter satisfies the
broker contract for the OpenAI Codex CLI specifically).

Linear: TIN-913 (in-place broker proof, broker-owned topology); TIN-938
(controlled remote app-server sidecar). GitHub issue: forthcoming.

Source references (codex repo, ref `main` @ `67849d9` 2026-05-03):
- `codex-rs/login/src/auth/manager.rs` — `AuthManager`,
  `UnauthorizedRecovery`, refresh flow.
- `codex-rs/app-server/src/message_processor.rs` — `ExternalAuthRefreshBridge`,
  `set_external_auth` (L96–161, L286).
- `codex-rs/app-server-protocol/schema/json/ChatgptAuthTokensRefresh{Params,Response}.json`
- `codex-rs/codex-api/src/api_bridge.rs` L80–104 — quota signal shape.
- `codex-rs/model-provider-info/src/lib.rs` L233–244 — base URL override.
- `codex-rs/model-provider/src/bearer_auth_provider.rs` L33–47 — wire headers.
- `codex-rs/exec/src/lib.rs` L1580–1588 — exec rejects external refresh.
- `codex-rs/tui/src/app/app_server_requests.rs` L136 — TUI silently drops it.

## 0.0 Current Implementation Checkpoint

TIN-948/TIN-949 are bounded skeleton slices, not the full adapter
described by the rest of this contract. They add `oauth-mux codex run`,
an oauth-mux-owned localhost wire proxy, and a synthetic smoke where a
stub Codex child keeps the same PID while the proxy observes quota
exhaustion, marks the selected route unavailable, and sends the next
request with a different account's fixture credentials. Runtime
`CODEX_HOME` is a per-session overlay copied from the selected account's
auth source; the adapter does not rewrite the account-local
`config.toml`.

Implementation update, 2026-05-05: the overlay now separates auth/config
authority from session authority. Auth/config remain mux-owned in the
temporary `CODEX_HOME`; `sessions/`, `history.jsonl`, `session_index.jsonl`,
and `shell_snapshots/` are bridged by reference to canonical Codex session
authority by default. `docs/spec/harness-session-authority-bridge-2026-05-05.md`
tracks the remaining live resume acceptance.

Implementation update, 2026-05-06: explicit live brokered resume now works
through the managed frame and proxy. The status artifact for that dogfood showed
canonical session authority, mux-owned auth/config, and live
`POST /backend-api/codex/responses` turns returning `status:200`. This proves
the managed frame and normal proxy path, not account-exhaustion success.

The current 429 implementation remains next-request recovery: the proxy returns
`429 usage_limit_reached` to Codex, marks the active account exhausted, and the
next request elects a different account. That is below the strict product bar if
the failed turn is visible. The next implementation target is a same-turn
handoff attempt that retries or recovers before Codex receives the quota
failure when a fallback account is selectable.

That smoke is structural evidence only. It uses local stubs and fake
fixture tokens, makes no provider calls, and keeps the adapter output at
`claim_level:"broker_owned"` while reporting
`synthetic_swap_observed:true`. It does **not** claim live
`next_turn_seamless`, provider-originated quota handling, same-thread
recovery, or unmanaged Codex TUI hot-swap.

## 0. Scope

This adapter exists to deliver the `oauth-mux codex` user entrypoint and
hit Level 3 (`next_turn_seamless`) of the broker claim ladder for
ChatGPT-subscription Codex usage. Stretch: Level 4
(`mid_turn_seamless`) via the wire-layer proxy path. Out of scope:
Codex API-key (non-subscription) auth, since muxing has no value when the
key is static; Codex over OpenRouter/Azure/`oss` provider, since those
auth surfaces are unrelated to the subscription quota problem.

## 1. The Two-Layer Architecture

The Codex adapter is one process that runs two cooperating mediators
against the spawned `codex app-server` child:

```
                        oauth-mux codex (adapter process)
                        │
                        ├─── MCP client ── speaks broker MCP over stdio
                        │                  to the oauth-mux daemon (or
                        │                  embeds the broker in-process
                        │                  for single-user mode)
                        │
                        ├─── JSON-RPC client (the IDE role) ──┐
                        │                                     │
                        │                                     ▼
                        │                            codex app-server (child)
                        │                            ── stdio JSON-RPC
                        │
                        └─── Wire-layer reverse proxy ──┐
                                                        │
                                                        ▼
                                          127.0.0.1:<port>/backend-api/codex
                                          (which forwards to chatgpt.com)
                                          ── HTTP+WS, signs requests with
                                             the currently-elected account
```

The IDE-role channel handles refresh/login/account-switch protocol events
the app-server initiates. The wire-layer proxy handles 429
`usage_limit_reached` events the app-server cannot itself recover from
(per §3, the app-server's `UnauthorizedRecovery` only fires on 401).

Without **both** layers, Level 3 is unreachable for quota exhaustion. With
both layers, Level 3 is the default and Level 4 is reachable.

## 2. Process Topology

### 2.1 Single-process default

`oauth-mux codex` resolves to a single adapter binary that:

1. Loads `~/.config/oauth-mux/config.json` (existing path; the broker's
   account pool comes from here).
2. Selects the initial route via broker `account/select` (or local
   selection if the user passed `--account <name>`).
3. Materializes that account's `auth.json`-equivalent tuple.
4. Writes a temporary, adapter-owned `CODEX_HOME` directory containing the
   selected account's `auth.json` and a generated `config.toml` whose
   selected custom provider (`model_provider = "oauth_mux_openai"` and
   `[model_providers.oauth_mux_openai]`) points at the wire-layer proxy.
   Codex 0.128+ rejects overriding the reserved built-in `openai`
   provider id. Session-authority paths are bridged per
   `docs/spec/harness-session-authority-bridge-2026-05-05.md`, not copied
   wholesale into this overlay. Operators may pass `--isolated-session-store`
   for a test/private namespace or `--session-home <path>` for an explicit
   canonical session authority.
5. Binds the wire-layer proxy on `127.0.0.1:<dynamic-port>`, with the
   proxy holding the account pool reference and the broker session id.
6. Spawns `codex app-server --listen stdio://` as a child, with
   `CODEX_HOME=<adapter-temp-dir>`.
7. Sends `initialize` with `capabilities.experimentalApi: true`.
8. Sends `account/login/start` with `type: "chatgptAuthTokens"` and the
   selected route's tuple, awaits `account/login/completed` and
   `account/updated`.
9. Becomes the JSON-RPC IDE-role client for the child for the rest of the
   session, AND the wire-layer proxy operator for the child's HTTP
   traffic.
10. Renders the user-facing terminal session per §5 (TUI strategy).

On normal exit, removes the temporary `CODEX_HOME` directory and notifies
broker via `surface/teardown`.

### 2.2 Daemon-attached mode (later)

When a long-running `oauth-mux daemon run` is present, the adapter SHOULD
prefer connecting to that daemon's broker socket rather than embedding
the broker in-process. The handshake is identical; only the transport
changes. This unlocks shared health/quota state across multiple concurrent
adapters (e.g. a `oauth-mux codex` session and a parallel `oauth-mux
claude` session sharing the broker's event log). Phase plan: not required
for Phase 1/2; light up after Phase 5.

## 3. The 401 vs 429 Handling Matrix

This is the crux. Codex's app-server treats authorization failure (401)
and quota exhaustion (429 + `usage_limit_reached`) on **different code
paths**, and only the 401 path invokes the `ExternalAuth` bridge. The
adapter must handle each correctly.

| Upstream signal | App-server reaction | Adapter response | Resulting claim level |
|---|---|---|---|
| `200` OK | Normal turn | Forward bytes through wire proxy unchanged | Level 2 baseline |
| `401 unauthorized` | `UnauthorizedRecovery` step machine: `Reload` → `RefreshToken` → `ExternalRefresh` (calls our IDE-role bridge via `chatgptAuthTokens/refresh`) | Adapter answers refresh request with current account's freshly-refreshed tuple (via broker `credential/refresh`) OR with the next account's tuple (via broker `account/swap`). App-server retries the same turn. | Level 3 if same-account refresh; Level 3+ if account-swapped within turn |
| `429 + body.error.type == "usage_limit_reached"` | Returns `CodexErr::UsageLimitReached` to the user; **does NOT call ExternalAuth** | Wire proxy intercepts BEFORE response reaches app-server. Reports `quota/observe`, calls `account/swap`, then path (a) silently retries upstream against the new account (returning a clean response to app-server — Level 4) or path (b) synthesizes a 401 to app-server, which then drives `ExternalRefresh`, which adapter answers with the new account (Level 3, app-server retries the same turn) | Level 4 (path a) or Level 3 (path b) |
| `429 + body.error.type == "usage_not_included"` | `CodexErr::UsageNotIncluded` (plan tier issue, not quota) | Wire proxy reports `quota/observe` with kind `tier_insufficient` and propagates to app-server unchanged. This is a degraded-account issue, not a swap-eligible one. | Level 2; surfaces handoff |
| Other `429` (rate limit, no usage-limit type) | `CodexErr::RetryLimit` | Wire proxy honors `Retry-After`, optionally swaps if `Retry-After > policy_threshold`, otherwise propagates | Level 2 or Level 3 depending on swap |
| Provider 5xx | App-server retries per its own policy | Wire proxy propagates; reports `quota/observe` with kind `provider_5xx` (no swap) | Level 2 |

**Decision: default to path (b) for Phase 2.** Path (b) — synthesize a 401
to drive `ExternalRefresh` — is safer because it goes through Codex's own
state machine (`UnauthorizedRecovery::ExternalRefresh` →
`from_external_access_token`), which means the in-memory `AuthManager`
cache is updated *correctly* per Codex's contract. Path (a) — silent
upstream retry — is cleaner-looking but bypasses Codex's auth-state
machine, which means Codex's in-memory `account_id` may now disagree with
what the wire is presenting; subsequent requests in the same conversation
could surface inconsistent header state. We pursue path (a) only after
Phase 2 wire capture proves no inconsistency arises (Q1 in the broker
spec).

## 4. Wire-Layer Proxy Spec

### 4.1 Endpoints to terminate

The proxy MUST handle, at the path prefix `/backend-api/codex` (matching
upstream's path layout — see `model-provider-info/src/lib.rs` L233–240):

- `POST /backend-api/codex/responses`
- `POST /backend-api/codex/responses/compact`
- `POST /backend-api/codex/memories/trace_summarize`
- WebSocket upgrade on the same base, protocol header
  `responses_websockets=2026-02-06` (per `core/src/client.rs` L132–134).

The proxy MUST forward all other paths under that prefix transparently
(future endpoints) and MUST NOT block on unknown paths.

### 4.2 Per-request header substitution

For every forwarded request, the proxy:

1. Reads the bound session's currently-elected account credential.
2. Replaces the inbound `Authorization` header with `Bearer
   <access_token>` from the elected account's tuple.
3. Replaces the inbound `ChatGPT-Account-ID` header with the elected
   account's `chatgptAccountId`.
4. Sets `X-OpenAI-Fedramp: true` if the elected account's id-token
   custom claim `chatgpt_account_is_fedramp` is true; absent otherwise.
5. Forwards to `https://chatgpt.com/backend-api/codex/...` with TLS
   verification ON against the system trust store. (No MITM CA install
   needed; the proxy speaks plaintext to the locally-bound app-server and
   speaks plain TLS to chatgpt.com.)

### 4.3 Response classification

For every response from upstream, before returning bytes to the
app-server, the proxy classifies status:

```
if status == 401:
    quota/observe(kind=auth_unauthorized, ...)
    return upstream response unchanged
elif status == 429:
    parse body for error.type
    if error.type == "usage_limit_reached":
        quota/observe(kind=quota_exhausted, resets_at=body.resets_at, ...)
        SWAP_DECISION = path(b)  # default Phase 2
        if SWAP_DECISION == path(b):
            account/swap(reason=quota_exhausted, ...)
            synthesize_401_to_app_server()  # short-circuit return
        else:  # path(a), gated behind capture evidence
            account/swap(...)
            silently_retry_upstream_with_new_account()
    elif error.type == "usage_not_included":
        quota/observe(kind=tier_insufficient, ...)
        return upstream response unchanged
    else:
        quota/observe(kind=rate_limited, retry_after=hdr, ...)
        return upstream response unchanged
elif status >= 500:
    quota/observe(kind=provider_5xx, ...)
    return upstream response unchanged
else:
    if status == 200: quota/observe(kind=ok, ...)
    return upstream response unchanged
```

### 4.4 Streaming responses

Codex uses SSE for streaming model output. The proxy MUST stream responses
through unchanged byte-for-byte to the app-server, with classification
deferred until the stream closes (or until an error frame is observed).

Mid-stream account swap is **not attempted in Phase 2**. If a 429
classification arrives mid-stream, the proxy completes the current stream
(error frames pass through) and the swap takes effect on the *next* turn
the app-server initiates. This is the honest shape; we do not pretend a
mid-stream re-key works against an SSE response that has already
committed.

### 4.5 WebSocket handling

If the WS upgrade variant is in use (`responses_websockets=2026-02-06`),
the proxy upgrades the inbound socket and opens a corresponding outbound
TLS WS to chatgpt.com, signed with the elected account's headers at
upgrade time. WS-level account swap mid-connection is **not implemented in
Phase 2**; the proxy closes the WS cleanly on `usage_limit_reached`
detection (which arrives over the WS frame stream as an error type the
app-server then surfaces) and lets the app-server reopen against the new
account on the next user turn. Phase 4+ may revisit if wire capture proves
WS reauth is feasible without thread-id loss.

## 5. TUI Strategy

The Codex TUI is a substantial product surface. The adapter has three
options for presenting the user-facing terminal session:

### Option A — Thin passthrough (Phase 1/2 default)

The adapter renders no rich TUI. It uses the `codex app-server`'s JSON-RPC
event stream to drive a minimal terminal interface: the user types
prompts, sees streamed model output, sees tool calls in a conventional
ANSI-formatted form, and sees status updates. The adapter does not try to
match Codex TUI's full feature set (split panes, file diffs as inline
patches, etc.). This is honest about what the adapter can render
correctly. Users who want the rich Codex TUI run bare `codex` and accept
no broker mux.

This is the Phase 1 ship target. Acceptable degradation for the early
adopter cohort because the broker mux is the value prop, not the TUI.

### Option B — Sibling TUI driving remote app-server (deferred)

The codex TUI binary itself is configured to connect to a remote
app-server (the one our adapter spawned) over a Unix socket / WebSocket.
The user sees the real Codex TUI; the adapter sits between TUI and
app-server.

**Currently blocked.** Per the deep-dive on `codex-rs/tui/src/lib.rs`,
the TUI embeds an in-process app-server and does not honor a remote
socket. Pursuing this path requires either an upstream contribution to
Codex (TUI gains `--remote ws://...` support) or a private fork.
Documented here so that if upstream lands such a flag, we can pivot
without re-architecting.

### Option C — Adapter-rendered rich TUI

The adapter implements its own rich TUI on top of the JSON-RPC event
stream. Big Zig lift. Considered post-Phase-5 once the broker contract
is proven across at least two adapters.

### Decision

Phase 1 ships Option A. Option B becomes default when upstream Codex
allows it. Option C is a roadmap stretch.

## 6. Account Boundary and Workspace Policy

Codex enforces a workspace boundary in `app-server` test
`v2/account.rs`: cross-account swap is rejected when a forced workspace
id is configured. The adapter MUST honor this:

1. Account pool entries carry an optional `workspace_id`. If present, the
   broker's `account/swap` will only return accounts with matching
   `workspace_id`.
2. The default is a "same profile only, no work/personal crossing" policy
   from the broker spec §2.2. The adapter does not relax this.
3. If `account/swap` returns `no_account_selectable` because workspace
   policy filtered the candidate pool, the adapter surfaces a typed
   handoff: `"no in-policy account available; the next eligible account
   is in a different workspace and policy forbids crossing"`.

## 7. Refresh Path

Two refresh triggers, both serialized through the broker:

### 7.1 Proactive refresh

The adapter watches the access-token JWT `exp` claim of the elected
account. When `exp` is within a configurable margin (default: 5 minutes),
the adapter calls `credential/refresh` with `trigger:
"proactive_exp"`. The broker performs the refresh against
`https://auth.openai.com/oauth/token` under its per-account mutex,
persists the new tuple, returns a fresh credential handle. The adapter
hot-replaces the wire-proxy's bound credential without a turn break.

### 7.2 Reactive refresh on 401

When the wire proxy sees a 401 from upstream, the response is propagated
to the app-server, which invokes its `UnauthorizedRecovery` machine. Step
3 (`ExternalRefresh`) reaches the adapter as a JSON-RPC
`chatgptAuthTokens/refresh` request. The adapter:

1. Calls broker `credential/refresh` for the current account
   (`trigger: "unauthorized_401"`).
2. If broker returns a fresh tuple: reply to `chatgptAuthTokens/refresh`
   with that tuple.
3. If broker returns `refresh_failed`: call `account/swap`, reply with
   the new account's tuple instead. App-server's
   `from_external_access_token` then installs the new account as the
   active one for the session.
4. If `account/swap` also fails: reply to `chatgptAuthTokens/refresh`
   with a JSON-RPC error. App-server surfaces auth failure to the user.
   Adapter records the typed handoff via `events/append`.

**Refresh-token race protection (per `openai/codex#9634`).** Concurrent
adapters MUST NOT both attempt to refresh the same account. The broker
serializes per-account; if a second adapter requests refresh while one is
in flight, the broker returns the result of the in-flight call (not a
fresh attempt). Adapters must accept that policy without retry.

## 8. Adapter CLI Surface

```
oauth-mux codex                                       # default: pick from default profile
oauth-mux codex --profile codex-max                   # specific profile
oauth-mux codex --account codex:max-1                 # pin to one account (no swap)
oauth-mux codex --session-home ~/.codex               # explicit session authority
oauth-mux codex --isolated-session-store              # test/private session namespace
oauth-mux codex --no-broker                           # bypass: bare codex, no mux (degraded)
oauth-mux codex --                                    # explicit args separator passes everything to codex
oauth-mux codex resume --last                         # forwarded to codex
oauth-mux codex exec "..."                            # forwarded; Phase 1 may not support exec
oauth-mux codex --json-status                         # JSON status frames to stderr while running
oauth-mux codex --json-status-file ./omux.ndjson      # JSON status frames to a file
```

`--no-broker` runs bare `codex` directly with no adapter (`execvp`); it
exists so users can disable the adapter without uninstalling it. The
adapter MUST NOT silently fall back to `--no-broker` mode on broker
errors; broker connection failure is a hard error.

## 9. JSON Status Frames

When `--json-status` is set, the adapter emits NDJSON to stderr, one frame
per significant event. When `--json-status-file <path>` is set, those
same frames go to the named file instead; this is the required artifact
path for live acceptance so real Codex terminal output cannot corrupt
oauth-mux evidence. Frame shapes are stable under broker `surface_version:
1`:

```jsonc
// adapter startup
{ "kind": "session_started", "session_id": "...", "selected_account": "codex:max-1", "claim_level": "broker_owned", "wire_proxy_addr": "127.0.0.1:54321" }

// target shape for a successful invisible quota handoff; not emitted by the
// current next-request-only 429 path
{ "kind": "account_swap", "from": "codex:max-1", "to": "codex:max-3", "reason": "quota_exhausted", "via": "wire_proxy_429_retry", "claim_level": "next_turn_seamless" }

// every refresh
{ "kind": "credential_refresh", "account": "codex:max-1", "trigger": "proactive_exp", "outcome": "ok" }

// resume authority preflight and writeback evidence
{ "kind": "resume_preflight", "mode": "last", "session_authority": "canonical_bridge", "rollouts_before": 42, "session_id_printed": false, "path_printed": false }
{ "kind": "resume_writeback", "mode": "last", "session_authority": "canonical_bridge", "changed_existing": 1, "created": 0, "session_id_printed": false, "path_printed": false }

// quota observation that did not trigger a swap
{ "kind": "quota_observed", "account": "codex:max-1", "kind_detail": "rate_limited", "retry_after_s": 12 }

// teardown before live quota-handoff proof remains broker_owned
{ "kind": "session_ended", "session_id": "...", "turns": 14, "swaps": 0, "final_claim_level": "broker_owned" }
```

These frames are the only structured surface the adapter publishes. The
adapter never logs token material, refresh-token bytes, raw JWT bodies,
or full response bodies.

## 10. Failure Modes and Refusals

The adapter MUST refuse to start in these conditions:

- Broker unreachable AND adapter is not in `--no-broker` mode.
- No accounts in the resolved profile / capability are selectable AND no
  user-mediated repair handoff is available.
- `codex` binary is not on `PATH` or does not respond to `app-server
  --listen stdio://`.
- The user's `~/.codex/config.toml` already has a non-managed provider
  block with a custom base_url that would be selected by the session AND
  the user did not pass `--allow-config-shadow`. (We will not silently
  override user config.)

The adapter MUST surface, not retry, on these:

- `account/swap` returns `no_account_selectable` after a quota event.
  (Surface a handoff; do not attempt to enroll a new account silently.)
- `credential/refresh` returns `refresh_token_invalidated` for the only
  selectable account. (Surface; user must re-login.)
- App-server child crashes. (Adapter exits non-zero with a typed message;
  does not respawn.)

## 11. Testing Strategy

### 11.1 Unit-level (fixtures)

- Wire-layer proxy: golden HTTP fixtures for each `429` body shape,
  verify the classification matrix in §3 produces the right
  `quota/observe` and the right adapter action.
- IDE-role client: golden JSON-RPC fixtures from Phase 0 wire capture,
  verify adapter answers `chatgptAuthTokens/refresh` correctly.

### 11.2 Local broker mocks

- Embedded broker with N synthetic accounts, verify
  `account/select` → `account/swap` cycle under each typed quota signal.

### 11.3 Local app-server smokes (existing surfaces, repointed)

The current `broker-401-smoke`, `broker-quota-smoke`,
`broker-refresh-smoke`, `broker-session-smoke` commands already exercise
real `codex app-server` children against local mocks. After Phase 2,
these smokes are repointed at the new adapter pipeline (they exercise the
adapter rather than ad-hoc broker code). They become the regression
suite for §3 behavior.

### 11.4 Live-spend proof (Phase 2 acceptance)

- Real interactive `oauth-mux codex` session, two enrolled accounts,
  account A near quota, account B credited. User runs prompts until
  account A exhausts. Verify: account B continues the session without a visible
  quota-failed turn when a fallback account is selectable,
  `claim_level: next_turn_seamless` is emitted only after that evidence,
  `oauth-mux codex` did not prompt the user, and the `codex` child process did
  not restart (verified by `ppid` stability across the swap). This is the
  metric.

### 11.5 ToS-honest paid-cohort soak (Phase 3)

- Multi-day cohort with 4 accounts, observed real exhaustion, recorded
  swap evidence. Negative results published if mid-turn (Level 4) is
  unreachable.

## 12. What This Adapter Does NOT Do

- Modify `~/.codex/auth.json` directly (we use a temporary CODEX_HOME
  per session).
- Defeat or attempt to defeat OpenAI rate-limit fingerprinting,
  Cloudflare bot defenses, or any other server-side throttling that
  isn't explicitly the per-account weekly quota signal.
- Restart the `codex app-server` child to recover from anything. Restart
  is not a recovery path; it is a session-ending failure.
- Render the full Codex TUI in Phase 1. (See §5.)
- Touch any non-Codex provider's auth state.
- Run any user's enrolled-but-not-current-session account through
  refresh on its own schedule. Refresh is on-demand, per session.

## 13. Migration of Existing Code

The current `runCodexBrokerRun`, `runCodexBrokerSessionSmoke`,
`runCodexAppServerLiveBrokerRun`, `runCodexBrokerFallbackDrill`, and
related helpers in `src/main.zig` already implement most of the IDE-role
JSON-RPC client and the local-mock infrastructure. The Phase 1 work is
mostly:

1. Extract a reusable `CodexAppServerClient` from those callsites into
   `src/adapters/codex/app_server_client.zig`.
2. Add `src/broker/mcp_server.zig` exposing the surface from the broker
   spec §2 over stdio.
3. Add `src/broker/account_pool.zig`, `src/broker/health.zig`,
   `src/broker/refresh.zig` (or refactor the existing `health.zig` /
   `oauth.zig` into the broker package).
4. Add `src/adapters/codex/wire_proxy.zig` for the §4 reverse proxy.
5. Add `src/adapters/codex/main.zig` for the adapter binary entry,
   delegated to from a new `codex` subcommand in `src/cli.zig`.
6. The `runStayAfloatLaunch`, `runCodexManaged`, `runStayAfloatObserve`
   surfaces stay during Phase 1/2 as Level 1 diagnostic-only paths, and
   are demoted in Phase 4 per the broker spec §5 Phase 4.

## 14. Acceptance Criteria

The adapter is acceptable when:

1. `oauth-mux codex` runs a one-account interactive session indistinguishable
   from bare `codex` modulo §5 TUI degradation.
2. `oauth-mux codex` runs a multi-account session and on observed
   live-account exhaustion swaps to a credited account in the same
   `codex app-server` child before Codex receives a visible quota-failed turn,
   emitting `claim_level: next_turn_seamless` only after that evidence.
3. The wire-layer proxy correctly classifies every entry of §3's matrix
   against captured fixtures.
4. The adapter never prints token material, refresh-token bytes, full
   JWT bodies, raw response bodies, or upstream account-id values that
   weren't already part of the broker session config.
5. The adapter never restarts its child to recover from any failure.
6. The adapter satisfies the broker spec's §3 MUST/MUST-NOT contract.

## 15. Open Adapter-Specific Questions

- **A1.** When the wire proxy synthesizes a 401 to the app-server (path
  b, §3), does the app-server invoke `ExternalRefresh` for the
  *currently-in-flight* turn or for the *next* turn? Affects whether
  Level 3 is per-turn or per-message. Resolved by Phase 0 capture.
- **A2.** Does `account/login/start` with `chatgptAuthTokens` (the
  re-login call we'd use for an account swap) work mid-session, or does
  it require a full app-server reinit? `broker-refresh-smoke` exercises
  the refresh path; we need a mid-session re-login smoke too.
- **A3.** What is the actual TUI feature gap a Phase 1 thin-passthrough
  imposes? File-by-file feature inventory of `codex-rs/tui` to scope
  Option A honestly before Phase 1 ships.
- **A4.** Does the adapter need to forge `Sec-Fetch-Site` / `Origin` /
  Cloudflare-relevant headers to chatgpt.com, or do bare `Authorization +
  ChatGPT-Account-ID` headers suffice? (`bearer_auth_provider.rs` only
  shows the latter; capture confirms.)
- **A5.** Which Codex files are required for managed resume parity:
  `sessions/` only, or also `session_index.jsonl`, `history.jsonl`, and
  `shell_snapshots/`? The answer belongs in the session-authority bridge
  smoke before live managed-frame resume is treated as parity.
