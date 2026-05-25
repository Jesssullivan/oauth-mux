# Codex Wire Evidence — Phase 0 Capture
Date: 2026-05-03
Status: TOOLING LANDED; OPERATOR CAPTURE PENDING. Source-confirmed
entries are pre-populated from the 2026-05-03 reality-check pass against
`openai/codex@67849d95`. Live operator-confirmed entries
(`OPERATOR-CONFIRM`) get filled by running
`scripts/capture-codex-wire.sh proxy` against a real authenticated
`codex` session and a real quota-exhausted account.

Anchor: `docs/spec/broker-mcp-contract-2026-05-03.md` §5 Phase 0.
Adapter consumer: `docs/spec/codex-adapter-contract-2026-05-03.md` §3
(401-vs-429 handling matrix), §4 (wire-layer proxy spec).

This document distills the wire-shape evidence the wire-layer proxy
and IDE-role JSON-RPC client implement against. Source-confirmed
entries flow from `openai/codex` source review at the cited
file:line; operator-confirm entries become observed shapes after
the live capture lands.

TIN-950 adds the capture/replay tooling only:

- `scripts/capture-codex-wire.sh preflight` writes a no-spend
  capture-readiness report with installed `oauth-mux` provenance,
  native Codex version, mitmproxy availability, current route fallback
  readiness, latest status verdict, and stale-process hints. Run this
  immediately before starting any intercepting proxy or live provider
  spend.
- `scripts/capture-codex-wire.sh` starts the operator-controlled
  mitmproxy HTTP capture path.
- `scripts/codex-wire-addon.py` writes reviewed, redacted per-flow JSON
  from that capture path.
- `scripts/capture-codex-wire.sh review captures/codex-wire-<TS>`
  summarizes endpoint/status coverage, extracts 429 quota shapes, and
  fails on obvious secret-like values before a capture is promoted.
- `scripts/test-cassette-upstream.py` replays reviewed capture JSON by
  `(method, path)`, ignoring query strings for route matching.
- `just smoke-codex-cassette-replay` proves the replayer on a tiny
  synthetic cassette without provider traffic.
- `just smoke-codex-capture-review` pins the offline reviewer: scrubbed
  quota fixtures pass and obvious bearer-token leaks fail.

The existing in-session smoke (`just smoke-codex-acceptance`) proves the
adapter/proxy can classify and substitute against synthetic versions of
these shapes. The cassette replay smoke proves the replay layer can
serve captured shapes once they exist. Live capture's job is still to
confirm the shapes themselves match upstream reality.

## Capture Provenance

- codex version: _OPERATOR-CONFIRM_  (`codex --version` of binary used)
- codex-rs commit: _OPERATOR-CONFIRM_  (from upstream tag matching the binary)
- ChatGPT subscription tier of capturing account: _OPERATOR-CONFIRM_
  (Free / Plus / Pro / Business / Enterprise — affects which 429 body
  type fires)
- Capture timestamp range: _OPERATOR-CONFIRM_
- Capture run directory: `captures/codex-wire-<TS>/`
- Capture preflight summary: _OPERATOR-CONFIRM_
  (`captures/codex-wire-<TS>/capture-preflight-summary.json`, recorded
  before the proxy was started)
- mitmdump version: _OPERATOR-CONFIRM_
- Capture review summary: _OPERATOR-CONFIRM_ (`capture-codex-wire.sh review`)
- Replay tooling: `scripts/test-cassette-upstream.py`
- Synthetic replay smoke: `just smoke-codex-cassette-replay`

## Capture Promotion Checklist

Before any captured flow is committed as a cassette or cited as live
evidence:

1. Run `scripts/capture-codex-wire.sh preflight` and confirm
   `ok:true`, `fallback_ready:true`, and `single_route_at_risk:false`
   unless the operator explicitly accepts a single-route-at-risk capture.
2. Run `scripts/capture-codex-wire.sh review captures/codex-wire-<TS>`
   against the capture root, not the raw `.flows` file.
3. Confirm the summary includes the expected path/status mix for the
   scenario being promoted: normal 200, 401 refresh, 429
   `usage_limit_reached`, compact, memory, or other Codex endpoint.
4. Confirm `redaction_failures` and `malformed` are empty.
5. Manually inspect the fixture-sized JSON selected for promotion.
   The reviewer catches obvious token/JWT/API-key strings; it is not a
   formal proof that all account-identifying material is gone.
6. Textual non-JSON responses such as `text/event-stream` may include
   `body_text` so the cassette replayer can serve realistic SSE frames.
   Keep only reviewed, fixture-sized text bodies and remove prompt,
   transcript, or account-identifying content before promotion.
7. Commit only scrubbed per-flow JSON. Do not commit
   `captures/**/flows.binary`.

## 1. Endpoints Observed

**Source-confirmed list (per `codex-rs/core/src/client.rs` L132–134):**

| Method | Path (relative to base_url) | Trigger | Streaming? | Auth headers |
|---|---|---|---|---|
| POST | `/responses` | every model turn | Yes (SSE) | `Authorization`, `ChatGPT-Account-ID`, optional `X-OpenAI-Fedramp` |
| POST | `/responses/compact` | conversation compaction | Likely streaming | same |
| POST | `/memories/trace_summarize` | memory summarization | Likely non-streaming | same |
| Upgrade | (same base) WS | `responses_websockets=2026-02-06` Beta | Bidirectional WS | same headers on upgrade request |

Adjacent endpoints (file uploads, cloud-tasks) carry the same auth
headers and are pass-through targets too: see `codex-rs/codex-api/src/files.rs`
and `codex-rs/backend-client/src/client.rs`.

`base_url` defaults to `https://chatgpt.com/backend-api/codex` for
ChatGPT-subscription auth (per
`codex-rs/model-provider-info/src/lib.rs` L233–242). Single field
override for both subscription and API-key paths.

_OPERATOR-CONFIRM_: capture wire shows EXACTLY these paths and no
others under `/backend-api/codex/`.

## 2. Request Header Set on a Normal Turn

**Source-confirmed full forward-unchanged set** (per
`codex-rs/login/src/auth/default_client.rs` L149–165 +
`codex-rs/core/src/client.rs` L114–117 +
`codex-rs/model-provider/src/bearer_auth_provider.rs` L33–47):

```
# Three auth-bound (the proxy substitutes these per-account)
Authorization: Bearer <id_token | access_token>
ChatGPT-Account-ID: <chatgpt_account_id>
X-OpenAI-Fedramp: true                  # only when account.fedramp

# Eight forward-unchanged (proxy MUST forward verbatim)
User-Agent: <originator>/<version> (<os> <ver>; <arch>) <terminal> (<suffix>)
originator: codex_cli_rs                # or other client identifier
x-codex-installation-id: <stable per-install id>
x-codex-turn-state: <STICKY-ROUTING TOKEN — DO NOT rotate mid-thread>
x-codex-turn-metadata: <per-turn blob>
OpenAI-Beta: responses_websockets=2026-02-06   # WS upgrades + other gates
traceparent: <W3C trace id>
tracestate: <W3C trace state>
x-openai-internal-codex-residency: us   # conditional
```

`x-codex-turn-state` is the load-bearing one. The wire proxy DROPS
this header on same-turn retry and post-swap turns (per `wire_proxy.zig`) —
every other header in this set is forwarded verbatim.

NOT sent (do not forge):
- `Sec-Fetch-Site` / `Sec-Fetch-Mode` (browser-only)
- `Origin` (browser-only)
- `x-stainless-*` (Stainless SDK; not the Rust client)

_OPERATOR-CONFIRM_: capture a normal turn; verify exactly this header
set, no surprise additions.

## 3. Normal-Turn Response Frames

**Source-confirmed** (per `codex-rs/exec/tests/fixtures/cli_responses_fixture.sse`):

SSE with explicit `event:` / `data:` framing. Empty-line event
separator. Parsed by `eventsource_stream` (per `core/src/client.rs`
L55).

```
event: response.created
data: {"type":"response.created","response":{"id":"resp1"}}
<blank line>
event: response.output_item.done
data: {"type":"response.output_item.done","item":{...}}
<blank line>
event: response.completed
data: {"type":"response.completed","response":{"id":"resp1","output":[]}}
<blank line>
```

Final boundary: `event: response.completed`.

The proxy MUST preserve byte-exact CRLFs and the empty-line event
terminator. Phase 2.1 streaming pumps bytes through verbatim via
Connection: close framing — the proxy never re-encodes SSE.

_OPERATOR-CONFIRM_: capture a normal turn; verify SSE framing matches
fixture shape.

## 4. 401 Unauthorized — Frame Sequence

**Source-confirmed**:

- HTTP request that triggered: any normal `POST /responses` with an
  expired or revoked access_token bearer.
- HTTP response status: 401, body usually empty or short JSON.
- Codex's behavior: `AuthManager` runs `UnauthorizedRecovery` step
  machine: `Reload` → `RefreshToken` → `ExternalRefresh`
  (per `codex-rs/login/src/auth/manager.rs` L1169–1221):
  1. Reload reads `auth.json` from disk in case external mutation.
  2. RefreshToken POSTs to `https://auth.openai.com/oauth/token`
     with refresh_token grant; persists fresh tokens via
     `persist_tokens` → `storage.save()`.
  3. Codex retries the original request with the fresh access_token.
- ExternalRefresh (the `chatgptAuthTokens/refresh` JSON-RPC bridge)
  is reachable only from `codex app-server` clients, NOT from the
  TUI's in-process app-server (per `tui/src/app/app_server_requests.rs`
  L136 + `exec/src/lib.rs` L1580–1588).

In the current adapter-owned child + wire-proxy topology:
- The proxy buffers 401 responses so it can make an evidence-preserving
  auth decision before Codex sees the failure.
- If another account is selectable, the proxy marks the failed account
  unauthorized in the in-process pool, drops `x-codex-turn-state`, and retries
  the same request against the fallback account. It emits
  `proxy_auth_same_turn_retry`. This is auth-continuity evidence, not quota
  exhaustion evidence.
- If no fallback account is selectable, the proxy returns the buffered 401 to
  codex unchanged and emits `proxy_observed_401_codex_handles`.
- Codex's RefreshToken path can still run entirely inside codex on the no-
  fallback path.
- During the same managed session, the proxy preserves Codex's refreshed
  same-account `Authorization` header instead of re-signing with stale
  oauth-mux materialized auth. This keeps Codex's native retry path
  authoritative when Codex receives and recovers from a 401 itself.
- At child exit, the adapter compares the managed overlay `auth.json`
  with the selected account's mux-owned auth source. If Codex refreshed
  tokens inside the overlay, oauth-mux imports that changed file back
  into the selected account source and emits a redacted `auth_writeback`
  status frame. This prevents the next managed frame from reusing an
  already-consumed refresh token. The import is compare-and-swap shaped:
  if another managed session changed the source after this overlay was
  created, oauth-mux reports `source_conflict:true` and does not
  overwrite that fresher source.
- `pool.markUnauthorized` is called only after fallback credentials have
  materialized for a replacement account. Without a selectable fallback, the
  proxy leaves the failed account to Codex's native refresh loop.
- If the managed session exits after unrecovered 401s and the overlay
  `auth.json` did not change, the adapter records account-credential health
  for the next launch and emits `auth_health_observed` with
  `quota_claim:false`. This is a local auth-source repair signal, not quota
  evidence and not a live account-substitution proof.

_OPERATOR-CONFIRM_: revoke a refresh_token externally, drive a turn,
verify (a) codex's AuthManager logs RefreshToken, (b) auth.json mtime
advances inside the managed overlay after the refresh, (c) the same
managed session's retry uses the child refreshed bearer, and (d) the
post-exit `auth_writeback` frame reports `changed:true` and
`written:true` without printing path or token material.

## 5. 429 + `usage_limit_reached` — Frame Sequence

**Source-confirmed body shape** (per `codex-rs/codex-api/src/api_bridge.rs`
L80–104, struct `UsageErrorBody` L127–138):

```json
{
  "error": {
    "type": "usage_limit_reached",
    "plan_type": "pro",
    "resets_at": 1788000000
  }
}
```

- Field casing: **snake_case** (`plan_type`, `resets_at`)
- `resets_at`: **unix-seconds (i64)** — decoded via
  `DateTime::<Utc>::from_timestamp(seconds, 0)`
- `plan_type` ∈ free/plus/pro/business/enterprise/edu

Headers seen on 429:
- `Retry-After` (sometimes; standard HTTP)
- `x-codex-active-limit` (active limit id, parsed by api_bridge L86–90)
- `x-codex-rate-limit-*` per-limit headers (parsed via
  `parse_rate_limit_for_limit`)

Codex's behavior on this status: typed `CodexErr::UsageLimitReached`,
NOT-retryable, surfaced to the user. Does NOT call `ExternalAuth` /
`chatgptAuthTokens/refresh` (per source review, confirmed).

The wire proxy:
- Buffers the response body (small JSON).
- Classifies as `quota_exhausted` with `resets_at` parsed from body.
- Calls `pool.markQuotaExhausted(account_id, resets_at)`.
- If a fallback account is selectable, elects it immediately, drops
  `x-codex-turn-state`, retries the same request, and returns the fallback
  response to codex. The original 429 is logged as
  `delivered_to_codex:false`.
- If no fallback account is selectable, returns the buffered failure and logs
  `proxy_same_turn_retry_unavailable`.

_OPERATOR-CONFIRM_: drive an account to weekly quota; capture the
exact body bytes; verify field names + casing match.

## 6. Other 429 Variants

**Source-confirmed `usage_not_included`** (sibling type per same
`UsageErrorBody` enum):

```json
{
  "error": {
    "type": "usage_not_included",
    "plan_type": "free"
  }
}
```

Means: this account's plan tier does not include Codex. NOT
swap-eligible (rotating won't fix a tier gap; the user needs to
upgrade or use a different account explicitly).

The wire proxy:
- Classifies as `tier_insufficient`.
- Does NOT mutate the pool.
- Does NOT swap accounts.
- Returns the 429 to codex so codex can surface the upgrade prompt.

This behavior is pinned by `just smoke-codex-tier-insufficient`.
`smoke-codex-acceptance` covers the swap-eligible
`usage_limit_reached` path; the tier-insufficient smoke is the
non-swap regression catch.

**Bare 429 (no `error.type`)**: rate-limited; classified as
`rate_limited`. Proxy honors `Retry-After`, optionally swaps if
`Retry-After` exceeds a policy threshold (Phase 2.2+). Default
behavior: propagate.

_OPERATOR-CONFIRM_: capture both variants if both are reachable
with available accounts; verify body shapes match.

## 7. WebSocket Upgrade

**Source-confirmed correction** (per `codex-rs/core/src/client.rs`
L131): `responses_websockets=2026-02-06` is sent as the HTTP header
`OpenAI-Beta: responses_websockets=2026-02-06` on the upgrade
request, **NOT as a `Sec-WebSocket-Protocol` value.** The original
spec was wrong on this; the wire proxy must not advertise it as a
WS subprotocol upstream.

The Phase 2 v1 wire proxy does NOT support WS upgrade; codex falls
back to chunked HTTP / SSE when the upgrade is rejected. Phase 2.2
adds WS pass-through.

_OPERATOR-CONFIRM_: capture an upgrade attempt (force WS via codex
config or the env that triggers it); verify `OpenAI-Beta` header
shape.

## 8. ID-Token Presence

**Source-confirmed**:
- `auth.json` always carries an `id_token` alongside `access_token`
  (per `codex-rs/login/src/auth/storage.rs` `AuthDotJson` L84–141).
- `id_token` is a JWT whose payload contains the
  `https://api.openai.com/auth` custom claim with
  `chatgpt_plan_type`, `chatgpt_user_id`, `chatgpt_account_id`,
  `chatgpt_account_is_fedramp` (per `codex-rs/login/src/token_data.rs`
  `parse_chatgpt_jwt_claims`).
- `Authorization` bearer is `tokens.access_token` (NOT `id_token`)
  per `bearer_auth_provider.rs` L33–47 — the id_token is consumed
  client-side for claim parsing only.

So: only the `access_token` rides the wire, but cross-account swaps
must carry consistent (access_token, account_id, plan_type) tuples
because the proxy's `ChatGPT-Account-ID` header is sourced from the
id_token's `chatgpt_account_id` claim. The materializer
(`broker_loader.zig::materializeChatgpt`) decodes both correctly.

_OPERATOR-CONFIRM_: capture the wire; verify `Authorization` carries
access_token only (not id_token); verify `ChatGPT-Account-ID`
matches the id_token's `chatgpt_account_id` claim.

## 9. DPoP / cnf-Claim Presence

**Source-confirmed: NO DPoP/cnf handling** (per repo-wide search of
`codex-rs/login` and `codex-rs/model-provider` for `DPoP`, `dpop`,
`cnf`: zero hits in Rust auth code). `bearer_auth_provider.rs`
treats the access_token as opaque bytes; no JWK thumbprint
computation; no `htm`/`htu`/`jti` proof construction.

This means: bearers are wire-portable across processes. The proxy
substituting `Authorization` headers per request is sound; no
`cnf`-claim mismatch risk.

If chatgpt.com edge enforced DPoP, the bare codex CLI would already
be broken. Therefore this is settled.

_OPERATOR-CONFIRM_: decode an access_token JWT (base64url-no-pad
the second segment); verify NO `cnf` claim in the payload. Verify
chatgpt.com responses never carry `WWW-Authenticate: DPoP`.

## 10. JSON-RPC Stdio Framing — `codex app-server`

**Source-confirmed contract** (per `codex-rs/app-server-protocol/schema/json/`):

- `account/login/start` with `type:"chatgptAuthTokens"`:
  ```json
  {
    "method": "account/login/start",
    "params": {
      "loginType": {
        "type": "chatgptAuthTokens",
        "tokens": {
          "accessToken": "<JWT>",
          "chatgptAccountId": "<id>",
          "chatgptPlanType": "pro"   // optional
        }
      }
    }
  }
  ```
  Gated behind `initialize.params.capabilities.experimentalApi: true`
  (per spec §0.1).

- Server emits `account/login/completed` then `account/updated` with
  `authMode:"chatgptAuthTokens"`.

- Server-initiated refresh request:
  ```json
  {
    "method": "account/chatgptAuthTokens/refresh",
    "params": { "reason": "unauthorized", "previousAccountId": "..." }
  }
  ```

- Client response shape:
  ```json
  {
    "result": {
      "accessToken": "...",
      "chatgptAccountId": "...",
      "chatgptPlanType": "..."
    }
  }
  ```

- 10-second `EXTERNAL_AUTH_REFRESH_TIMEOUT` per
  `codex-rs/app-server/src/message_processor.rs` L96–161.

The current `oauth-mux codex run` child+proxy path does NOT use this
protocol. It is available for broker-mediated automation and future
adapter modes (`app_server_client.zig`).

_OPERATOR-CONFIRM_ (only if exercising broker-mediated path): capture
JSON-RPC stdio frames during a real `codex app-server --listen
stdio://` run; verify method names + params shapes match.

## 11. Open Questions Resolved

Per the truthing pass on `jess/broker-mcp-codex-adapter`. Cross-ref
broker-mcp-contract §8 + codex-adapter-contract §15.

- **Q1** (mid-turn account header rewrite acceptance): RESOLVED —
  leaning contradicted. Issue `openai/codex#16894` plus
  `x-codex-turn-state` sticky-routing token at `core/client.rs:116`
  give strong evidence per-`sub` server-side thread state. Phase 2
  default is between-turn swap (Level 3); Level 4 mid-turn is
  gated on positive _OPERATOR-CONFIRM_ capture.
- **Q2** (cross-account thread id reuse): STANDING — Level 5 not
  claimed. Honest negative result.
- **Q3** (TUI-embedded app-server response to refresh): MOOT in the
  current child+proxy topology. We don't drive
  `chatgptAuthTokens/refresh` through the TUI's embedded
  app-server; codex owns its own UnauthorizedRecovery on
  propagated 401s.
- **Q4** (id_token cache vs login/start re-derive): STANDING but
  non-blocking. The current child+proxy topology sidesteps
  `account/login/start` at runtime.
- **Q5** (DPoP/cnf): RESOLVED — no DPoP/cnf in codex-rs auth code.
  Bearers are wire-portable.
- **A1** (synthesized-401 retries current vs next turn): MOOT in the
  current child+proxy topology. We don't synthesize 401; the wire
  proxy returns the upstream 429 unchanged and codex starts a new
  turn on the next user input.
- **A2** (mid-session `chatgptAuthTokens` re-login): STANDING but
  non-blocking. The current child+proxy topology doesn't re-login at
  runtime.
- **A3** (TUI feature gap for thin-passthrough): MOOT — we don't
  thin-passthrough; we exec real codex.
- **A4** (additional headers required by chatgpt.com): RESOLVED —
  the eight-header forward-unchanged set is the source-confirmed
  answer. _OPERATOR-CONFIRM_ that the captured wire shows no
  header NOT in this list (which would indicate hidden CF/abuse
  signal we're missing).

## 12. Implications for Phase 2

The current child+proxy topology is what has shipped so far. Source
review answered most questions; live capture's job is to confirm the
wire shapes match these assumptions.

If live capture surfaces:

- **Header NOT in §2's list that the wire proxy strips**: add to the
  forward-unchanged copy in `wire_proxy.zig::copyForwardingHeaders`.
- **Header NOT in §2's list that the proxy needs to substitute**:
  add to the substitute set (§2's auth-bound trio currently).
- **429 body shape divergent from §5/§6**: update
  `wire_proxy.zig::classify` to match.
- **WS upgrade traffic actually goes through `Sec-WebSocket-Protocol`**:
  contradicts source review; rerun source check before changing
  proxy behavior.

The in-session smoke (`smoke-codex-acceptance`) proves the proxy
correctly classifies and substitutes against a synthetic
`usage_limit_reached` shape. The cassette replay smoke proves reviewed
captures can be replayed deterministically once operator evidence lands.
Live capture is for "do the actual chatgpt.com responses match these
shapes byte-for-byte" not "what shapes does the proxy support."
