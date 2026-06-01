# Broker MCP Contract — The oauth-mux Product Reframe
Date: 2026-05-03
Status: ANCHOR. This document is the truth source for the oauth-mux product.
Replaces, in priority: any spec or doc that frames restart, supervised
relaunch, route-warming, or `prepared_fallback` as the success metric.

Linear: TIN-491 (root muxing architecture), TIN-738 (daemon RFC parent),
TIN-913 (in-place broker proof). Supersedes the framing of TIN-911 (now
diagnostic-only). GitHub anchor issue: forthcoming.

External anchors used for this contract:

- MCP 2025-06-18 transports define JSON-RPC over stdio and Streamable HTTP;
  stdio launches the server as a subprocess and reserves stdout for valid MCP
  messages: https://modelcontextprotocol.io/specification/2025-06-18/basic/transports
- JSON-RPC 2.0 is transport-agnostic over process, socket, HTTP, or other
  message channels: https://www.jsonrpc.org/specification
- Codex CLI is an open-source local terminal agent and authenticates via
  ChatGPT account or API key: https://developers.openai.com/codex/cli
- OpenAI's Codex responses proxy shows the same `base_url` + `wire_api =
  "responses"` interposition shape this contract relies on:
  https://github.com/openai/codex/blob/main/codex-rs/responses-api-proxy/README.md
- OAuth references for this work: RFC 6749 core, RFC 6750 bearer tokens,
  RFC 7636 PKCE, RFC 8252 native apps, RFC 8693 token exchange, and RFC 9449
  DPoP.

Current evidence review:

- `docs/spec/test-and-coverage-review-2026-05-05.md` is the
  current-main assessment of tests, synthetic evidence, live route truth,
  and remaining Level 3 gaps. It is descriptive only; this broker
  contract remains the product source of truth.
- `docs/spec/harness-session-authority-bridge-2026-05-05.md` records the
  managed-frame store split required for normal `resume`/history behavior:
  oauth-mux owns auth/config overlays, but adapters must retain or bridge
  harness session authority instead of hiding or copying it wholesale.
- `docs/spec/codex-managed-resume-ux-refactor-2026-05-06.md` records the
  managed Codex daily-use refactor required after the first live resume
  attempt failed before exercising the bridge: first-class
  `oauth-mux codex resume ...`, strict parser behavior, status-file parent
  creation, and regression guards.
- `docs/spec/in-agent-reauth-handoff-contract-2026-05-14.md` records the
  agent/MCP handoff contract for reauth prompts: agents can inspect, display,
  acknowledge, and ask for consent, but must not silently run upstream login,
  spend provider calls, or mutate credential stores.

## 0. The One Success Metric

The product succeeds when, and only when, this is true:

> The user runs `oauth-mux <harness>` (e.g. `oauth-mux codex`). The harness
> behaves like the real one. The active subscription account exhausts its
> quota. **Another credited account is seamlessly substituted in place.** The
> harness process is not restarted. The user is not prompted. No conversation
> thread is lost that the underlying provider protocol does not itself force
> us to lose.

Everything else in this repository — `stay-afloat`, `route explain`,
`prepared_fallback`, `supervise`, `managed`, `broker-*` smokes, daemon ticks,
launchd recipes — is either a stepping stone toward that bar or diagnostic
plumbing. None of them is the product.

If a future spec, ticket, commit message, or README sentence frames any of
those surfaces as "the success" or "the fallback if seamless mux is hard,"
that sentence is wrong by construction and must be deleted on sight. The
maintainer has called this drift out by name. We will not relapse.

## 1. The Architectural Reframe

### 1.1 oauth-mux is the broker. Each harness has an adapter.

This diagram is the target architecture, not a claim that every named adapter is
implemented today. Current repo truth:

- Codex is the reference harness with managed launch/resume, broker-owned
  app-server proof, and live managed quota handoff evidence.
- Claude is a provider-proof lane only: `CLAUDE_CONFIG_DIR` isolation,
  `enroll claude`, and `auth-status` via `claude auth status --json`.
- `oauth-mux claude` is not yet an implemented harness adapter and must not be
  presented as stay-afloat or broker-seamless proof.

```
                    ┌── oauth-mux (broker daemon) ─────────────┐
                    │  • Multi-provider account pool           │
                    │  • Health, quota, refresh state          │
                    │  • Refresh serialization (per account)   │
                    │  • MCP server: account/* quota/* …       │
                    │  • Event log + redacted evidence         │
                    └──────────────┬───────────────────────────┘
                                   │ MCP / JSON-RPC over stdio
                  ┌────────────────┼────────────────┐
                  ▼                ▼                ▼
           Codex adapter    future Claude    future Cursor…
                  │                │                │
                  ▼                ▼                ▼
           codex app-server  claude code CLI   cursor agent
                  │                │                │
                  ▼ (+ colocated wire-layer proxy when needed)
           chatgpt.com / api.anthropic.com / …
```

The broker knows nothing about ChatGPT, Cloudflare, refresh-token rotation
quirks, TUI rendering, or any harness's binary layout. It owns: accounts,
health, quota state, refresh policy, event log, and the MCP method surface
adapters speak.

The adapter is the *only* place per-harness intelligence lives. The Codex
adapter knows about `codex app-server`, the `chatgptAuthTokens` mode, the
`UnauthorizedRecovery` step machine, the `chatgpt.com/backend-api/codex`
wire shape, and how to render or pass through the Codex TUI. A future Claude
adapter must do the same kind of per-harness work for Claude's own auth,
session, quota, and reload surfaces; the existing Claude provider proof does
not satisfy that adapter contract.

### 1.2 MCP is the cross-process protocol

The broker exposes its surface as **MCP server methods over stdio**. JSON-RPC
2.0, batched, well-versioned. We pick MCP for three reasons that compound:

1. Codex's `app-server --listen stdio://` is already MCP-shaped JSON-RPC.
   Adopting MCP at the broker surface means our Codex adapter speaks the
   same shape upstream and downstream.
2. Any MCP-aware client (other agents, future harnesses, the user's own
   tooling) can register `oauth-mux` as a tool and consume the broker
   primitives directly — `account/select`, `quota/observe`,
   `account/refresh` — without needing to be one of our adapters.
3. The protocol is versioned and auditable. A Codex protocol drift won't
   silently break adapters that were correctly speaking the broker contract.

Concretely: the broker process can be invoked as `oauth-mux mcp` for stdio MCP
clients today. A future daemon/unix transport must speak the same method
surface before it is advertised as a broker host; the current daemon socket
remains experimental status/control plumbing and must not be treated as the
broker MCP transport.

### 1.3 The user-facing entrypoints become the adapters

The product surface presented to users is the adapter command, not raw
`codex` plus a sidecar:

```bash
oauth-mux codex   [args passed through to codex-equivalent UX]
# future adapters, after per-harness proof:
oauth-mux claude  [args passed through to claude-equivalent UX]
oauth-mux cursor  [...]
oauth-mux pi      [...]
```

The cost the user accepts: they type `oauth-mux <harness>` instead of
`<harness>`. In return: account exhaustion is invisible.

Bare `codex`/`claude`/etc. continue to work — we do not modify the upstream
binaries — but bare-mode users do not get seamless mux. That is honest
labelling, not a product limitation we hide.

Until a non-Codex adapter exists, use the provider-proof and enrollment surfaces
for those providers. For Claude, that means `oauth-mux enroll claude ...`,
`CLAUDE_CONFIG_DIR` user-mediated login, `doctor runtime`, `probe
--capability auth-status`, and `stay-afloat --once` as a diagnostic route-state
check. It does not mean `oauth-mux claude` seamless handoff exists.

## 2. Broker MCP Method Surface

Method names use slash-segmented namespaces in MCP convention. Every method
takes JSON params and returns JSON results. All identifiers are opaque
strings; no token material ever crosses the broker surface in either
direction.

Versioning: methods are stable within `surface_version` major. The current
major is `1`. Methods may add optional fields without bumping. Removals or
semantic changes bump major. `surface/info` reports the major.

### 2.1 Discovery and lifecycle

#### `surface/info`
Returns the broker's surface major, build, supported transport list, and
declared capabilities.
```jsonc
{
  "surface_version": 1,
  "build": "oauth-mux 0.2.0+broker",
  "transports": ["stdio"],
  "transport_detail": {
    "stdio_broker": true,
    "unix_broker": false,
    "daemon_socket_contract": "experimental_socket_stub",
    "daemon_hosts_broker": false
  },
  "capabilities": ["accounts", "quota", "credentials", "policy"],
  "capabilities_detail": {
    "account_list": true,
    "account_select": true,
    "account_swap": true,
    "credential_materialize": true,
    "credential_materialize_scope": "adapter_stdio_only",
    "credential_refresh": false,
    "quota_observe": true,
    "quota_status": true,
    "events_append": false,
    "events_subscribe": false,
    "policy_get": true,
    "policy_request_admission": false
  }
}
```

#### `surface/handshake`
Adapter announces itself and the harness it brokers for. Broker assigns a
session id used by all subsequent calls.
- Params: `{ "adapter": "codex", "adapter_version": "...", "session_pid": int, "harness_target": "codex 0.128.0" }`
- Returns: `{ "session_id": "<opaque>", "policy": {...}, "claim_floor": "broker_owned" }`

#### `surface/teardown`
Adapter signals clean exit. Broker drops session-scoped state, retains event
log entries.

### 2.2 Accounts

Account identity is `provider:account` (e.g. `codex:max-3`). Accounts are
configured out of band; the broker never enrolls accounts mid-session.

#### `account/list`
Lists accounts the calling adapter is allowed to see, scoped by profile.
- Params: `{ "session_id": "...", "profile": "codex-max", "capability": "codex-max" }`
- Returns: `{ "accounts": [ { "id": "codex:max-1", "selectable": true, "liveness": "live", "availability": "available", "next_eligible_at": null }, ... ] }`

#### `account/select`
Adapter asks the broker to pick a credited account for an upcoming request.
Broker applies health/quota/policy and returns the chosen identity plus an
opaque **credential handle** the adapter uses to materialize the actual
secret on its own side.
- Params: `{ "session_id": "...", "profile": "...", "capability": "...", "exclude": ["codex:max-3"] }`
- Returns: `{ "account": "codex:max-1", "credential_handle": "<opaque>", "claim": { "level": "broker_owned", "spare_fallback_ready": true } }`
- Errors: `no_account_selectable` (typed reason: `quota_only`, `dead_only`, `policy_blocked`).

The broker does not return token bytes. The credential handle resolves on
the adapter side via `credential/materialize` (§2.3) so we keep the secret
in the adapter, not the broker, and the wire never carries tokens.

#### `account/swap`
Adapter signals "the current account is unusable; give me the next one."
Broker marks the current account quota-exhausted (or other typed reason),
selects the next, returns it.
- Params: `{ "session_id": "...", "current_account": "codex:max-1", "reason": "quota_exhausted", "evidence": { "http_status": 429, "body_class": "usage_limit_reached", "resets_at": 1788000000 } }`
- Returns: same shape as `account/select`, plus `previous_marked: { "as": "quota_exhausted", "until": 1788000000 }` and explicit claim fields such as `requires_adapter_turn_completion:true`.
- Errors: `no_account_selectable` with the same typed reasons.

`account/swap` is the load-bearing method. It is what makes
"`account A` exhausts → `account B` takes over" a single atomic broker
operation that the adapter requests when its harness shows it the
exhaustion signal.

`account/swap` itself remains a broker-owned replacement selection. It must
not emit `claim.level:"next_turn_seamless"` merely because a replacement was
found. The adapter or proxy promotes to `next_turn_seamless` only after it
observes the next turn complete against the replacement account.

### 2.3 Credentials

#### `credential/materialize`
Adapter resolves an opaque handle into the secret material it needs to
present to its harness. This call is local-only on the adapter side when the
adapter and broker share an address space; it crosses MCP only when the
adapter is in a different process.
- Params: `{ "session_id": "...", "credential_handle": "...", "shape": "chatgpt_auth_tokens" | "anthropic_oauth_bearer" | ... }`
- Returns: shape-specific token tuple. Broker MAY refuse to materialize tokens over a non-stdio transport; adapters MUST accept the refusal and fall back to local resolution.

Token material is the only data type that gets shape-specific responses.
Everything else is provider-neutral.

#### `credential/refresh`
Adapter notifies the broker that the upstream issued a refreshed token (or
asks the broker to perform the refresh against the provider's OAuth token
endpoint, when admitted). Broker serializes per account, persists, returns
the new handle.
- Params: `{ "session_id": "...", "account": "...", "trigger": "proactive_exp" | "unauthorized_401" | "external_event" }`
- Returns: `{ "credential_handle": "...", "exp_unix": 1788000123 }`
- Errors: `refresh_failed` with typed reason (`refresh_token_expired`, `refresh_token_reused`, `refresh_token_invalidated`, `provider_5xx`, `policy_denied`).

Refresh-token rotation per OAuth 2.1 §4.3.1 is enforced here: the broker
holds a per-account mutex around refresh so two concurrent adapters can't
race a refresh-token reuse fault (the failure mode tracked in
`openai/codex#9634`).

### 2.4 Quota and observability

#### `quota/observe`
Adapter reports quota/rate-limit evidence it observed in the wire path.
Broker incorporates into account health.
- Params: `{ "session_id": "...", "account": "...", "capability": "...", "kind": "quota_exhausted" | "rate_limited" | "auth_unauthorized" | "ok", "http_status": 429, "headers": { "x-codex-active-limit": "...", "retry_after": "..." }, "body_class": "usage_limit_reached", "resets_at": 1788000000 }`
- Returns: `{ "recorded": true, "now_selectable": false, "next_eligible_at": 1788000000 }`

#### `quota/status`
Snapshot of all known account quota state in the calling adapter's profile.
- Params: `{ "session_id": "...", "profile": "...", "capability": "..." }`
- Returns: `{ "accounts": [ { "id": "...", "availability": "available" | "rate_limited" | "quota_exhausted" | "cooldown", "next_eligible_at": ... } ], "selectable_count": 2 }`

### 2.5 Events

#### `events/append`
Adapter records a redacted, structured event into the broker's local event
log (replaces ad-hoc per-command event writers in `src/repair_state.zig`).
- Params: `{ "session_id": "...", "kind": "account_swap" | "session_started" | "refresh_completed" | ..., "fields": {...redacted...} }`
- Returns: `{ "appended": true, "event_id": "..." }`

#### `events/subscribe` (server-initiated stream)
Broker pushes events to subscribed adapters. Used so a long-running adapter
sees account-state changes that originated elsewhere (e.g. operator ran
`oauth-mux account quarantine` from another shell).

### 2.6 Policy

#### `policy/get`
Returns the effective admission policy for the session.
- Returns: `{ "allowed_budgets": ["free_local","free_command"], "allow_interactive": false, "allow_mutating": false, "spend_admitted_for_session": false }`

#### `policy/request_admission` (interactive)
Adapter requests human approval for an action above current policy. Broker
surfaces the request as a handoff and waits up to a bounded timeout. The
broker NEVER auto-approves; default response is denial.

### 2.7 What is NOT in the surface

Explicitly out of scope, by design:

- **No `process/restart`, `session/respawn`, `harness/relaunch`.** Restart
  is not a broker primitive. It's not even a degraded fallback the surface
  knows how to express. If an adapter cannot hold its harness up via
  `account/swap` + `credential/refresh` + `quota/observe`, that adapter has
  failed; it MUST report failure honestly via `events/append` and exit. The
  broker will not pretend a respawn met the metric.
- **No `auth/login_browser` or device-flow initiation.** Account enrollment
  (the OAuth code flow that mints fresh refresh tokens) lives in the
  enrollment surface, not the broker session surface. The broker will refer
  an adapter to `oauth-mux enroll <provider> --account <name>` via a
  handoff; it will not silently open a browser.
- **No `provider/probe`.** Adapters do not ask the broker to "go talk to
  ChatGPT." Adapters observe their own wire and report via `quota/observe`.
  Out-of-session probes live in the existing `oauth-mux probe` CLI surface.

## 3. Adapter Contract

Every adapter MUST, MAY, and MUST NOT, exactly:

### 3.1 MUST

1. Speak MCP `surface_version: 1` against the broker.
2. Call `surface/handshake` before any other method.
3. Call `account/select` (or `account/swap`) before presenting credentials
   to its harness for any request the broker is supposed to govern.
4. Materialize tokens via `credential/materialize` (or local equivalent
   that the adapter can prove is broker-authorized).
5. Report every observed quota/rate-limit/auth event from its wire path
   via `quota/observe` *before* attempting recovery.
6. On its harness exhibiting account-blocked behavior, attempt `account/swap`
   exactly once per turn boundary. On the second attempt failing, surface a
   typed handoff and stop — no retry storms.
7. Report a clean, machine-readable claim level in its session status that
   is bounded by what it actually achieved this session. The default ceiling
   is `broker_owned`; higher claim levels (`current_process_swap`,
   `mid_turn_seamless`) require positive evidence in this session.
8. Redact tokens, refresh tokens, id tokens, account ids (where reasonable),
   and credential file paths from anything it emits to the broker, the
   user's terminal in JSON mode, and the event log.

### 3.2 MAY

1. Spawn its harness as a child, wrap its stdio, render a TUI, run a wire-
   layer proxy under it, install temporary config files, set env — anything
   inside its own process boundary. The broker doesn't know.
2. Maintain its own per-session cache of materialized credentials, as long
   as it invalidates on `account/swap` and on `events/subscribe`
   account-state changes.
3. Decline to broker for harness operations the broker can't govern (e.g.
   adapter renders a banner: "this command runs without oauth-mux mux") and
   exit 0 transparently.

### 3.3 MUST NOT

1. Restart its harness child to recover from an account exhaustion. Restart
   is not a broker outcome. If the adapter cannot do in-place swap, it MUST
   report `seamless: false` in its session claim and surface the failure to
   the user, not silently respawn.
2. Materialize tokens behind the broker's back (read `auth.json` directly
   without going through `account/select` first). Per-account pools belong
   to the broker.
3. Print token material to stdout/stderr/JSON.
4. Claim a higher claim level than the broker's `claim_floor` for the
   session.
5. Modify upstream-CLI-owned credential stores (e.g. write to
   `~/.codex/auth.json` directly) without an explicit
   `credential/refresh` admission from the broker for that account.

## 4. Claim Levels

The five-level ladder from `background-stay-afloat-daemon-contract-2026-05-02.md`
is collapsed and corrected. The new ladder, in increasing strength:

| Level | Name | Meaning | Required Evidence |
|---|---|---|---|
| 0 | `unmuxed` | Adapter ran the harness without broker involvement. | n/a (default for bare `codex`) |
| 1 | `prepared_fallback` | The next harness invocation can pick a healthy account. **Not a session-level claim. Strictly an out-of-session readiness state.** | Broker has selectable accounts in profile. |
| 2 | `broker_owned` | Adapter is brokering the harness. Account selection passed through `account/select`. | Adapter session opened, at least one `account/select` succeeded. |
| 3 | `next_turn_seamless` | On account exhaustion, the next conversation turn lands on a fresh account. **No process restart, no user prompt.** Same harness process. Same conversation context where the protocol allows. | At least one observed `account/swap` succeeded mid-session and the next turn completed against the new account. |
| 4 | `mid_turn_seamless` | Even an in-flight turn that hits exhaustion is recovered against a fresh account before the user sees an error. | Wire-layer evidence of an upstream 429-with-usage-limit being silently retried against the next account, and the harness receiving a clean response. |
| 5 | `cross_session_thread_continuity` | The conversation thread itself is preserved across the account swap. | Provider protocol evidence; not assumed. May not be achievable for ChatGPT subscription where `sub` claim binds threads server-side. Honestly labelled as "may not exist; will not pretend." |

Levels 0–2 are infrastructure. **Level 3 is the explicit success metric of
this product.** Level 4 is the stretch goal we will pursue but not claim
without wire evidence. Level 5 is where we will publish negative results
honestly if the upstream provider precludes it.

The previous `current_process_hotswap` / `supervised_restart` /
`per_request_muxing` / `unmanaged_tui_hotswap` flag soup is **deleted from
the surface**. Code emitting those flags should migrate to the level enum
above. The `supervised_restart` flag in particular is removed from claim
JSON entirely; restart is not a claim, it is a non-event.

## 5. Phase Plan

### Phase 0 — Wire and protocol capture
**Goal:** Replace assumptions with observed traffic before any code lands.
**Output:**
- A capture script that runs `mitmproxy` between a real `codex app-server`
  and `chatgpt.com/backend-api/codex`.
- A markdown spec in `docs/spec/codex-wire-evidence-2026-05-XX.md` that
  records: full message ordering for a normal turn, exact frames after a
  401, exact frames after a 429-with-usage-limit on a *real* exhausted
  account, the WebSocket upgrade auth shape, whether `id_token` is sent
  alongside access token, presence of any `cnf` / DPoP claim.
- A second capture script for the JSON-RPC stdio side: every method emitted
  by `codex app-server` during normal turn, login, refresh, and quota
  failure.
**Success bar:** Phase 1 is grounded in observed shapes, not inferred ones.
**No code yet.**

### Phase 1 — Broker MCP server + Codex adapter MVP
**Goal:** `oauth-mux codex` runs against a single account and is parity with
bare `codex`.
**Deliverables:**
- `oauth-mux mcp` exposes `surface/info`, `surface/handshake`,
  `account/list`, `account/select`, `account/swap`,
  `credential/materialize`, `quota/observe`, `quota/status`, and
  `policy/get`. Stdio transport only. `credential/refresh`, `events/*`,
  and policy admission return typed not-implemented responses until later
  slices wire those capabilities.
- `oauth-mux codex` adapter: spawns `codex app-server --listen stdio://`,
  drives the JSON-RPC, renders a thin terminal pass-through, materializes
  one selected account's tokens via the broker.
- Adapter reports `claim.level: "broker_owned"` (Level 2).
**Success bar:** A user can run `oauth-mux codex` and have a normal one-
account session indistinguishable from `codex`.

### Phase 2 — Multi-account swap (the metric)
**Goal:** Hit Level 3 (`next_turn_seamless`).
**Deliverables:**
- Account pool wired into `account/select` and `account/swap`.
- Codex adapter colocated wire-layer proxy in front of the app-server's
  HTTP traffic to `chatgpt.com`. Detects upstream 429 +
  `usage_limit_reached`. On detection: reports `quota/observe`, calls
  `account/swap`, materializes the new credentials, and either (a) silently
  retries the upstream request against the new account, or (b) synthesizes
  a 401 to the app-server to drive `UnauthorizedRecovery::ExternalRefresh`,
  which the adapter answers with the new account's tuple via the
  `chatgptAuthTokens/refresh` JSON-RPC reply.
- Adapter reports `claim.level: "next_turn_seamless"` only when an actual
  in-session swap succeeded.
**Success bar:** Real `oauth-mux codex` interactive session. Account A
exhausts. Account B continues the conversation in the same `codex` process.
No restart. No prompt. **This is the metric.**

### Phase 3 — Refresh, policy posture, paid-cohort soak
**Goal:** Production-honest behavior under provider rules.
**Deliverables:**
- Per-account refresh against `auth.openai.com/oauth/token`, serialized
  per account behind the broker's per-account mutex.
- Documented policy posture: subscription/account rotation is policy-sensitive
  and must be labeled as operator-owned behavior. We implement the mechanism
  only with explicit account enrollment and redacted evidence; we do not
  market it as quota evasion. Current posture lives in
  `docs/policy/tos-posture-2026-05-05.md`; it should not be linked from
  first-run or public promotion copy until Level 3 is live-proven and the
  posture is re-reviewed.
- Paid-cohort soak proof of Level 3 across at least 3 enrolled accounts and
  at least one observed real exhaustion-then-swap.

### Phase 4 — Demote the route-warming theater
**Goal:** Remove every CLI surface and spec sentence that lets the team
relapse into restart-as-success.
**Deliverables:**
- Keep `--max-restarts` / `--restart-on-exit-code` /
  `--restart-on-codex-usage-limit` as legacy compatibility aliases only until
  the next breaking CLI window. New docs, completions, and examples use
  `stay-afloat observe` with classification-shaped flags.
- Remove `supervised_restart` from every JSON claim emission.
- `stay-afloat launch` and `codex managed` continue to exist as Level 1
  preparation surfaces, but their docs explicitly state "this is not the
  product; see `oauth-mux codex` for the brokered seamless path."
- The public README is removed while the repository truth is being rebuilt.
  Any future README must lead with `oauth-mux codex` and demote the catalog of
  broker-* commands to a "diagnostic surfaces" appendix.
- Linear TIN-911 title and goal rewritten.

### Phase 5 — Second adapter (Claude)
**Goal:** Validate the broker MCP contract against a non-Codex harness.
**Deliverables:**
- `oauth-mux claude` adapter, same MUST/MAY/MUST NOT contract.
- Any broker surface change required to accommodate Claude's auth shape is
  a contract bug, fixed in the broker; we do not branch the adapter's
  expectations.
- Promotion of `surface_version` to `1.x` if optional fields are added,
  `2` if Codex's needs leaked into the surface.

### Phase 6 — Public surface promotion
**Goal:** Other tools can plug in.
**Deliverables:**
- Publish broker MCP method shapes as a versioned external spec.
- Document third-party adapter authoring under
  `docs/spec/harness-adapter-pattern.md`.
- Reference adapter implementations stay in-tree.

## 6. Source-of-Truth Hierarchy (updated)

1. `AGENTS.md` (repo root)
2. **This file** (`docs/spec/broker-mcp-contract-2026-05-03.md`) — the
   product anchor. Any older spec that conflicts with this is wrong by
   default.
3. `docs/spec/codex-adapter-contract-2026-05-03.md` — Codex adapter
   contract for the first harness implementation.
4. `docs/spec/harness-session-authority-bridge-2026-05-05.md` — harness
   store-boundary contract for auth/config/session/cache/evidence state.
5. `docs/spec/harness-adapter-pattern-2026-05-03.md` — general adapter
   pattern for non-Codex harnesses.
6. `justfile`, `flake.nix`, `build.zig`, `src/`
7. Other docs/spec/ files. The following are explicitly demoted to
   historical/diagnostic-only and must carry that label in their preamble:
   - `docs/spec/observed-child-diagnostic-contract-2026-05-02.md`
     (diagnostic child observation only; restart is not a product behavior)
   - `docs/spec/stay-afloat-supervisor-contract-2026-05-01.md` (predates
     the broker reframe; reads as if supervision is the product)
   - `docs/stay-afloat-wrappers.md` (recipes are diagnostic; the product
     entrypoint is `oauth-mux <harness>`)

The 5-level "seamless" ladder from
`docs/spec/background-stay-afloat-daemon-contract-2026-05-02.md` is
**superseded by §4 above**. The line at L239 of that spec — "a Codex-
specific wrapper can relaunch a child Codex process when the selected route
changes" — is **deleted by this contract**. It was the load-bearing
sentence that let restart-as-near-term-product back into the doc set, and
it goes now.

## 7. Anti-Patterns to Refuse

When reviewing PRs, specs, or commit messages going forward, refuse on
sight:

- "Supervised restart is the near-term Codex stay-afloat behavior."
- "`prepared_fallback` is the success state for the daemon."
- "If in-place swap proves hard, we'll fall back to wrapper restart."
- "`stay-afloat launch` is the user-facing entrypoint."
- "Same-thread quota recovery is unproven; therefore the product can't
  promise seamless mux." (The product promises Level 3 — `next_turn_
  seamless`. Same-thread is Level 5 and is honestly labelled as a
  may-not-exist stretch.)
- Any new claim-level flag that is not in §4. The flag soup is closed.

## 8. Open Questions Carried Honestly

These are unresolved and will be answered by Phase 0 capture or Phase 1/2
implementation. They are NOT excuses to soften the metric.

- **Q1.** When the wire-layer proxy converts an upstream 429 into a
  silent retry against the next account, does the Codex app-server
  receive the response with the new `ChatGPT-Account-ID` header without
  rejecting the conversation thread? If no, we drop to next-turn (Level 3)
  rather than mid-turn (Level 4); we do not pretend.
- **Q2.** Does the `chatgpt.com/backend-api/codex` backend honor a
  conversation thread id minted under account A when the next request
  carries account B's bearer? If no, Level 5 is provably out of reach
  and we publish the negative result.
- **Q3.** How does the Codex TUI's in-process app-server respond to its
  embedded server emitting `chatgptAuthTokens/refresh` when the
  embedded client (per `tui/src/app/app_server_requests.rs:136`) drops it?
  Does it surface a user-visible failure, or stall? If it stalls, we
  cannot pretend to support unmodified `codex` even at Level 1; this
  affects the labelling of `oauth-mux exec` for non-adapter use.
- **Q4.** Is the `id_token` cache inside `AuthManager` (the JWT-claim
  surface for `chatgpt_account_is_fedramp` etc.) re-derived on
  `account/login/start.chatgptAuthTokens` or held from initial login?
  Affects whether mid-session account swap honors cross-account FedRAMP
  policy correctly.
- **Q5.** What is the exact `cnf`/DPoP presence on a 2026-05-03 minted
  ChatGPT subscription token? Captured by Phase 0 and resolved before
  Phase 2 ships.

These questions belong in the spec, not in commit-message footnotes that
get lost.

## 9. Definition of Done

This contract is satisfied when:

1. `oauth-mux codex` is the documented, default user entrypoint for
   ChatGPT-subscription Codex usage in this repository.
2. A real interactive `oauth-mux codex` session can survive observed live
   account A quota exhaustion by transparently continuing on account B,
   with claim level emitted at runtime as `next_turn_seamless` (or
   `mid_turn_seamless` once Phase 2 path (a) lands).
3. The CLI surface contains no flag, command, or doc sentence that frames
   restart, `prepared_fallback`, or `supervised_restart` as the product
   success metric.
4. The Claude adapter exists and consumes the same broker MCP surface
   without per-harness shape leaking into the broker.
5. The broker's MCP method surface is documented externally and stable
   under a published `surface_version`.

Anything less is partial. We will say so plainly.
