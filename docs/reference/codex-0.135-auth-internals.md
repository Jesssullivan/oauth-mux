<!-- AUDIT-GENERATED DRAFT (2026-06-03 architecture audit workflow wf_a60ca68c).
     Grounded in repo evidence but NOT line-by-line human-verified — treat as a
     strong draft; verify specifics against source before citing as canonical. -->

# Codex 0.135 Auth/Home/Refresh Internals — oauth-mux Engineering Reference

**Version**: Codex CLI 0.135.0 (macos-aarch64)  
**Status**: Binary-only; source extracted from strings output, wire captures (codex-rs refs), and oauth-mux adapter evidence  
**Audience**: oauth-mux engineers implementing Codex broker and refresh semantics  
**Date**: 2026-06-03  

## Overview

Codex 0.135 is a subscription-aware OpenAI Codex CLI. It stores authentication
state in `$CODEX_HOME/auth.json`, runs a managed session authority in SQLite
databases, and implements an `AuthManager` that handles credential refresh,
account switching, and quota observation. oauth-mux mediates Codex sessions via
a wire-layer proxy and account pool to enable seamless quota-driven account
rotation.

## 1. Authentication Model: auth.json

### 1.1 File Location and Discovery

- **Primary**: `$CODEX_HOME/auth.json` (default `~/.codex/auth.json`)
- **Native override**: no supported `CODEX_AUTH_FILE` override has been proven
  in the raw Codex 0.135 binary.
- **Observed discovery order**: CODEX_HOME/auth.json → ~/.codex/auth.json

The local Home Manager wrapper observed on `neo` exports `CODEX_AUTH_FILE`, but
that is wrapper behavior, not native Codex evidence. Do not design oauth-mux
around `CODEX_AUTH_FILE` until a raw-binary live proof shows Codex honoring it.
As of this audit, managed auth still has to flow through `CODEX_HOME/auth.json`.

### 1.2 File Schema

```json
{
  "auth_mode": "chatgpt",
  "OPENAI_API_KEY": null,
  "tokens": {
    "access_token": "<JWT; used as Authorization bearer>",
    "id_token": "<JWT; contains chatgpt claims>",
    "refresh_token": "rt.1.<opaque; OAuth 2.0 grant token>",
    "account_id": "<UUID from id_token claim>"
  },
  "last_refresh": "2026-06-03T01:51:47.750809Z"
}
```

**Field semantics:**
- `auth_mode`: Enum {chatgpt | openai_api_key | agent_identity | ...}. Defines which token source is active.
- `OPENAI_API_KEY`: Only set if auth_mode=openai_api_key. Codex out-of-scope for muxing (static key; no quota per-account).
- `tokens.access_token`: JWT, opaque to Codex; passed as `Authorization: Bearer <token>`. NOT used for code generation itself; only wire auth.
- `tokens.id_token`: JWT, decoded client-side via Codex's TokenData parser. Contains custom claim `https://api.openai.com/auth` with:
  - `chatgpt_account_id`: UUID (same as tokens.account_id)
  - `chatgpt_plan_type`: String ∈ {free, plus, pro, business, enterprise, edu}
  - `chatgpt_user_id`: User UUID
  - `chatgpt_account_is_fedramp`: Boolean
  - `chatgpt_subscription_active_start`: ISO8601 timestamp
  - `chatgpt_subscription_active_until`: ISO8601 timestamp
  - `groups`: Array (typically empty)
- `tokens.refresh_token`: Opaque OAuth 2.0 refresh grant. Format: `rt.1.` prefix followed by base64url content. **Single-use per OAuth 2.1 §4.3.1**: Each refresh consumes this token; provider issues a new one in response.
- `tokens.account_id`: UUID matching id_token.chatgpt_account_id. Redundant for Codex; used by oauth-mux for account routing.
- `last_refresh`: ISO8601 timestamp of last successful credential/refresh call.

### 1.3 When Codex Writes auth.json

Codex writes via `AuthManager.persist_tokens()` → `storage.save()`:

1. **Startup refresh** (if token not present or expired)
2. **UnauthorizedRecovery RefreshToken step** (after 401 on /responses request)
3. **Explicit refresh** via Codex TUI / exec / app-server (user-initiated or broker-mediated)

**Not written by Codex:**
- Config overrides (those remain in config.toml)
- Session state (that lives in state_5.sqlite, logs_2.sqlite, history.jsonl)

**oauth-mux writeback** (post-exit): Compares managed overlay auth.json with selected account source. If Codex modified tokens during the session (e.g., successful refresh inside the overlay), oauth-mux atomic-compares back to the source (failing gracefully if another process wrote first).

---

## 2. Home and Session Authority: CODEX_HOME vs CODEX_SQLITE_HOME

### 2.1 Directory Structure (Codex 0.135)

**CODEX_HOME** (auth/config authority):
```
~/.codex/
├── auth.json                 # ← Codex reads/writes auth state here
├── config.toml              # ← Behavior config (MCP, features, model defaults, etc.)
├── installation_id          # ← Stable per-install identifier
├── version.json             # ← Cache of latest available version
├── config.json              # ← Legacy/migration format (not actively used)
├── app-server-daemon/       # ← App-server state (not in managed overlay)
├── cache/                   # ← HTTP cache, embeddings, etc.
├── log/                     # ← CLI logs (separate from session logs)
├── memories/                # ← Memory databases (goals_1.sqlite, memories_1.sqlite)
├── backups/                 # ← Credential/session backups (not in managed overlay)
├── plugins/                 # ← Custom MCP plugins
└── sessions/                # ← LEGACY: pre-0.132 rollout store
    ├── 2026/
    │   └── <thread-id>.jsonl  # ← Conversation history (migrated to state_5.sqlite in 0.132+)
    └── ...
```

**CODEX_SQLITE_HOME** (session authority, Codex 0.132+):
```
~/.codex/
├── state_5.sqlite           # ← Thread metadata, resume state
├── state_5.sqlite-wal       # ← Write-ahead log
├── state_5.sqlite-shm       # ← Shared memory for concurrent reads
├── logs_2.sqlite            # ← Session logs, transcript
├── logs_2.sqlite-wal
├── logs_2.sqlite-shm
├── goals_1.sqlite           # ← Goals database
├── goals_1.sqlite-wal
├── goals_1.sqlite-shm
└── memories_1.sqlite        # ← Memories database
    ├── memories_1.sqlite-wal
    └── memories_1.sqlite-shm
```

### 2.2 oauth-mux Managed Home (Canonical Bridge Mode)

**Goal**: Keep mux-owned auth/config while preserving native session authority.

**Managed overlay structure:**
```
<canonical_authority>/.oauth-mux/managed-codex-homes/omux-managed-codex-<hash>/
├── auth.json                    # ← MUXED: selected account's tokens
├── config.toml                  # ← MUXED: generated proxy config + preserved user settings
├── installation_id              # ← MUXED: copied from selected account
├── state_5.sqlite → <symlink>   # ← CANONICAL: points to ~/.codex/state_5.sqlite
├── state_5.sqlite-wal → <symlink>
├── state_5.sqlite-shm → <symlink>
├── logs_2.sqlite → <symlink>    # ← CANONICAL: points to ~/.codex/logs_2.sqlite
├── logs_2.sqlite-wal → <symlink>
└── logs_2.sqlite-shm → <symlink>
```

**Env set for child Codex:**
- `CODEX_HOME=<managed_overlay_path>` — points to mux-owned auth/config
- `CODEX_SQLITE_HOME=<canonical_authority>` — points to real session store

This means:
- Codex reads auth from mux overlay (session-specific tokens)
- Codex reads/writes session to canonical location (shared across managed sessions)
- Native `codex resume` sees all sessions (same canonical authority)
- SQLite lock contention checked on spawn (diagnostic; not fatal by default as of 2026-06-02)

### 2.3 Legacy Session Authority (pre-0.132)

If state_5.sqlite not present, Codex falls back to:
- `~/.codex/sessions/` — JSONL conversation histories
- `~/.codex/history.jsonl` — CLI command history
- `~/.codex/session_index.jsonl` — Session metadata index
- `~/.codex/shell_snapshots/` — Shell env snapshots

oauth-mux symlinks these legacy files when present, preserving backward compatibility.

### 2.4 Managed Home Lifecycle (as of 2026-06-02)

**Creation:**
1. oauth-mux selects an account (route)
2. Creates `~/.oauth-mux/managed-codex-homes/omux-managed-codex-<hash>/`
3. Copies selected account's auth.json into overlay
4. Generates config.toml (preserving user tables, stripping oauth-mux routing conflicts)
5. Symlinks state_5.sqlite*, logs_2.sqlite*, etc. to canonical authority
6. Sets CODEX_HOME and CODEX_SQLITE_HOME for child

**On exit:**
1. Scrubs auth.json, installation_id, generated config.toml from overlay
2. Leaves symlinks and bridge directory intact (so any recorded session paths remain resolvable to native Codex)
3. If isolated-session-store flag: removes entire overlay (disposable mode)

This avoids poisoning canonical SQLite rows with temp paths that don't exist after session exit.

---

## 3. Refresh Flow and Token Rotation

### 3.1 Codex AuthManager Lifecycle

**AuthManager** is an in-process cached snapshot of auth state. Key invariants:

- **Loaded once** at process start from CODEX_HOME/auth.json
- **Reloaded on demand** via `reload()` (checks disk file; ignores external mutations by default)
- **reload_if_account_id_matches()** refuses cross-account swaps (guards work/personal boundaries)
- **UnauthorizedRecovery** step machine handles 401 (Reload → RefreshToken → ExternalRefresh)

### 3.2 Refresh Workflow

**Trigger**: 401 Unauthorized on any /backend-api/codex/responses request.

**Steps** (per AuthManager.UnauthorizedRecovery, codex-rs release 0.128.0+):

1. **Reload**
   - Re-reads auth.json from disk (in case external mutation)
   - Compares account_id; refuses if mismatched (cross-account guard)

2. **RefreshToken**
   - POSTs to `https://auth.openai.com/oauth/token`
   - Grant: `refresh_token=<tokens.refresh_token>`
   - Receives new `access_token`, `id_token`, `refresh_token` (new RT issued by provider)
   - Calls `auth_manager.persist_tokens()` → writes updated auth.json
   - Returns new access_token to caller

3. **ExternalRefresh**
   - **Available only in brokered app-server mode** (JSON-RPC `chatgptAuthTokens/refresh`)
   - **NOT available in TUI or exec** (per codex-rs/tui/src/app/app_server_requests.rs:136 + exec/src/lib.rs:1580–1588)
   - Emits `account/chatgptAuthTokens/refresh` to external client (e.g., oauth-mux broker)
   - Waits 10s (EXTERNAL_AUTH_REFRESH_TIMEOUT) for response with new tokens
   - If timeout, falls back to RefreshToken path

**Key insight**: In the current oauth-mux `codex run` child+proxy topology, Codex receives 401s directly and runs RefreshToken internally. oauth-mux does not intercept the refresh; it observes the result and imports changed tokens post-exit.

### 3.3 Refresh Token Rotation (OAuth 2.1 §4.3.1)

**Single-use enforcement**:
- Each successful refresh **consumes** the old refresh_token
- Provider issues a **new refresh_token** in the response
- Codex atomically updates auth.json with new token
- Old token becomes invalid (reuse yields `refresh_token_reused` error)

**Race prevention** (oauth-mux broker):
- Per-account mutex serializes RefreshToken calls
- Before consuming refresh_token, re-reads auth.json under lock
- Detects if another process already refreshed
- Prevents concurrent double-refresh (race tracked in openai/codex#9634)

**Failure modes** (typed errors from broker.credential/refresh):
- `refresh_token_expired`: Token past expiration (provider-defined window, typically months)
- `refresh_token_reused`: Token already consumed in prior refresh (race or replay)
- `refresh_token_invalidated`: Explicit revocation (user action, security event, logout)
- `provider_5xx`: Upstream auth service error (transient; retry policy applies)
- `policy_denied`: oauth-mux policy forbids refresh (e.g., account disabled locally)

**Post-session writeback** (oauth-mux):
- Compares managed overlay auth.json (possibly modified by Codex) with selected account source
- If changed: imports new tokens via compare-and-swap (fails gracefully if source changed in parallel)
- Redacted status frame reports `changed:true`, `written:true` without printing path or token material
- Next launch uses refreshed token from source (no stale token reuse)

### 3.4 Refresh Token Locking: In-Process vs Cross-Process

**In-process** (within oauth-mux broker):
- File-backed mutex per account (via broker_loader.zig)
- Serializes multiple refresh calls on same account
- Atomic compare-and-swap when re-reading file under lock

**Cross-process**:
- Codex 0.135 manages its own refresh via UnauthorizedRecovery (runs inside Codex process)
- oauth-mux does NOT hold the Codex process during refresh; Codex refreshes independently
- oauth-mux imports the result post-exit (atomic writeback)
- Two concurrent managed sessions on same account:
  - Session A: runs Codex, hits 401, performs RefreshToken internally
  - Session B: runs Codex, different overlay, hits 401, performs RefreshToken independently
  - Both may win the race and import to the same source (later import wins compare-and-swap)
  - No data loss; refresh token always moves forward (monotonic)

---

## 4. Quota and Entitlement Signals

### 4.1 Plan Type (Entitlement)

**Source**: id_token JWT claim `https://api.openai.com/auth.chatgpt_plan_type`

**Values**: free | plus | pro | business | enterprise | edu

**Usage in Codex**:
- Decoded client-side (not used for wire auth; wire only uses access_token bearer)
- Passed to oauth-mux via id_token claim parsing
- Used by broker to classify account capability (e.g., "pro can use Codex; free cannot")

**Not a usage counter**: Plan type is a SKU identifier, not a rate limit. It does not decrease or reset. It indicates whether the account tier includes Codex access.

### 4.2 Quota Exhaustion (429 + usage_limit_reached)

**Trigger**: Weekly/monthly usage limit reached on Codex requests.

**HTTP response**:
```
HTTP/1.1 429 Too Many Requests
Content-Type: application/json

{
  "error": {
    "type": "usage_limit_reached",
    "plan_type": "pro",
    "resets_at": 1788000000
  }
}
```

**Fields**:
- `type`: Always `usage_limit_reached` for quota exhaustion
- `plan_type`: Current tier (free, plus, pro, etc.) — same as id_token claim
- `resets_at`: Unix seconds (i64) when limit resets. Decoded via `DateTime::<Utc>::from_timestamp(resets_at, 0)`

**Headers on 429**:
- `Retry-After`: Seconds to wait before retry (standard HTTP; may be absent)
- `x-codex-active-limit`: Identifier of which limit was hit (parsing via api_bridge)
- `x-codex-rate-limit-*`: Per-limit details (request count, window, etc.)

**Codex behavior**:
- Receives error as typed `CodexErr::UsageLimitReached`
- Does NOT retry
- Does NOT call ExternalRefresh (auth is valid; quota is the issue)
- Surfaces error to user (UI prompt to upgrade or wait)

**oauth-mux wire-proxy response**:
- Buffers the 429 response body (small JSON)
- Classifies as `quota_exhausted`
- Calls `pool.markQuotaExhausted(account_id, resets_at)`
- If fallback account selectable: swaps immediately, retries request, returns 200 to Codex
- If no fallback: returns buffered 429 to Codex (Codex surfaces to user)
- Logs as `proxy_same_turn_retry` (when swapped) or `proxy_same_turn_retry_unavailable` (when not)

### 4.3 Tier Insufficient (usage_not_included)

**Condition**: Account's plan does not include Codex (e.g., free tier).

**HTTP response**:
```
HTTP/1.1 429 Too Many Requests
Content-Type: application/json

{
  "error": {
    "type": "usage_not_included",
    "plan_type": "free"
  }
}
```

**Key difference from usage_limit_reached**:
- No `resets_at` (tier cannot be upgraded by waiting)
- Means: account must upgrade SKU or use a different account with Codex access

**oauth-mux wire-proxy response**:
- Classifies as `tier_insufficient`
- Does NOT call `pool.markQuotaExhausted()` (not temporary; tier gap doesn't fix itself)
- Does NOT swap accounts (rotating won't help)
- Returns 429 unchanged to Codex
- Codex surfaces upgrade prompt to user

**Broker observability** (via quota/observe MCP):
- `kind: tier_insufficient` or `kind: quota_exhausted` (depending on error.type)
- Broker records account as unavailable (tier_insufficient) or quota-blocked (quota_exhausted)
- Different remediation: tier_insufficient requires user action; quota_exhausted auto-resets at resets_at

### 4.4 Rate Limited (bare 429)

**Condition**: Transient rate limit (not quota; burst protection).

**HTTP response**:
```
HTTP/1.1 429 Too Many Requests
Retry-After: 60

(body may be empty or non-JSON)
```

**Codex behavior**:
- Receives as `CodexErr::RateLimited`
- May respect Retry-After
- May retry (up to policy)

**oauth-mux classification**:
- `kind: rate_limited`
- Does not mark account quota-exhausted
- May optionally swap if Retry-After > policy threshold (Phase 2.2+; currently propagates)

### 4.5 Broker Quota Observability Contract

**MCP method**: `quota/observe`

**Params**:
```json
{
  "session_id": "<session-uuid>",
  "account": "<account-name>",
  "capability": "<capability-name>",
  "kind": "quota_exhausted" | "rate_limited" | "auth_unauthorized" | "ok",
  "http_status": 429,
  "headers": {
    "x-codex-active-limit": "...",
    "retry_after": "..."
  },
  "body_class": "usage_limit_reached" | "usage_not_included" | ...,
  "resets_at": 1788000000
}
```

**Returns**:
```json
{
  "recorded": true,
  "now_selectable": false,
  "next_eligible_at": 1788000000
}
```

**Broker side effects**:
- Records quota evidence in route health log
- Marks account unavailable (based on kind and resets_at)
- Subsequent account/select calls exclude unavailable accounts (unless forced)
- Status summary shows which accounts are quota-blocked and when they reset

---

## 5. Wire Protocol: Headers and Requests

### 5.1 Auth-Bound Headers (Proxy Substitutes Per-Account)

```
Authorization: Bearer <access_token>
ChatGPT-Account-ID: <account_id>
X-OpenAI-Fedramp: true  # Only when account.fedramp
```

**Codex sources these from**:
- Authorization: tokens.access_token (JWT)
- ChatGPT-Account-ID: id_token.chatgpt_account_id claim (or tokens.account_id)
- X-OpenAI-Fedramp: id_token.chatgpt_account_is_fedramp claim

**oauth-mux proxy behavior**:
- Rewrites Authorization and ChatGPT-Account-ID for fallback accounts
- Drops X-OpenAI-Fedramp if fallback account does not have fedramp enabled

### 5.2 Forward-Unchanged Headers (Proxy Must Not Rewrite)

```
User-Agent: <originator>/<version> (<os> <ver>; <arch>) <terminal> (<suffix>)
originator: codex_cli_rs
x-codex-installation-id: <stable-per-install>
x-codex-turn-state: <STICKY-ROUTING-TOKEN>  # ← LOAD-BEARING; dropped on retry/swap
OpenAI-Beta: responses_websockets=2026-02-06
traceparent: <W3C-trace-id>
tracestate: <W3C-trace-state>
x-openai-internal-codex-residency: us  # Conditional
```

**Critical**: `x-codex-turn-state` is a sticky routing token. oauth-mux drops this header on:
- Same-turn retry (after account swap)
- Post-swap turns (new account, new thread)

Keeping this header when switching accounts risks upstream server-side session state corruption (thread pinning to wrong account).

### 5.3 Endpoints

**Source-confirmed** (per codex-rs/core/src/client.rs):

| Method | Path | Purpose | Streaming | Auth |
|--------|------|---------|-----------|------|
| GET | /backend-api/codex/responses | Upgrade for WebSocket | bidirectional WS | Bearer, Account-ID |
| POST | /backend-api/codex/responses | Normal turn (SSE fallback) | event-stream | Bearer, Account-ID |
| POST | /backend-api/codex/responses/compact | Conversation compaction | likely SSE | Bearer, Account-ID |
| POST | /backend-api/codex/memories/trace_summarize | Memory summarization | likely SSE | Bearer, Account-ID |
| GET | /backend-api/codex/models | Model availability | JSON | Bearer, Account-ID |
| POST | /backend-api/codex/analytics-events/events | Telemetry | JSON | Bearer, Account-ID |

**WebSocket upgrade** (Codex 0.132+):
- HTTP GET with `Upgrade: websocket` header
- OpenAI-Beta header: `responses_websockets=2026-02-06` (NOT Sec-WebSocket-Protocol)
- Server responds HTTP 101 Switching Protocols
- oauth-mux 0.1.12 returns HTTP 426 Upgrade Required (WS not yet supported; Codex falls back to SSE)

---

## 6. Secrets and Redaction Policy

### 6.1 Token Materials (Never Log)

- `access_token` (JWT)
- `id_token` (JWT)
- `refresh_token` (opaque rt.1.* string)
- HTTP Authorization header value (full bearer token)

**Safe to log** (redacted):
- Token JWT claims (e.g., account_id, plan_type, iat, exp) — decode and log claim values only
- Token length or type identifier (e.g., "JWT access_token" vs "refresh_token")
- First/last 4 chars of token (for correlation, never full token)

### 6.2 Account Identifiers (Redactable)

- `account_id` (UUID)
- `chatgpt_user_id` (UUID)
- `chatgpt_account_is_fedramp` (boolean, safe)

**Policy**: Redact in normal output. Include only as correlated pairs in logs (e.g., "account_1 → account_2 swap").

### 6.3 File Paths (Redactable)

- `CODEX_HOME` path
- Managed overlay paths
- Session file paths (rollout JSONL, SQLite, etc.)

**Policy**: Log as labels (e.g., "canonical_authority", "managed_overlay_path", "state_db_bridged") without full paths. Include paths in operator-only diagnostic logs with per-log consent.

### 6.4 Session Content (Redactable)

- Conversation transcripts
- Shell snapshots
- Memory content

**Policy**: Never log in default mode. Operator-only diagnostic logs may include (with explicit flag and user confirmation).

---

## 7. Error Cases and Recovery

### 7.1 401 Unauthorized (Invalid or Expired Token)

**Detection**: HTTP 401 on /backend-api/codex/responses

**Codex recovery** (AuthManager.UnauthorizedRecovery):
1. Reload auth.json from disk
2. POST refresh_token to OAuth endpoint
3. Persist new tokens to auth.json
4. Retry original request with new access_token

**Success indicator**: Retry returns HTTP 200; Codex sees response as if 401 never happened.

**oauth-mux additional handling** (wire-proxy):
- Buffers 401 response (may be evidence)
- If account marked as selectable and fallback exists: marks failed account unauthorized, swaps, retries
- Otherwise: passes 401 to Codex (Codex runs its own refresh)
- Post-exit: imports refreshed tokens from overlay to account source

### 7.2 429 Quota Exhausted

**Detection**: HTTP 429 with `error.type: usage_limit_reached`

**Codex behavior**: Surfacesto user as non-retryable error. Suggests upgrade or retry after reset.

**oauth-mux handling**:
- Buffers 429 response
- Classifies as quota_exhausted
- Calls pool.markQuotaExhausted(account_id, resets_at)
- If fallback account selectable: swaps, drops x-codex-turn-state, retries
- If no fallback: returns buffered 429 to Codex

**Recovery timeline**: Account becomes selectable again at resets_at timestamp (provider resets weekly/monthly).

### 7.3 Refresh Token Consumed (refresh_token_reused)

**Trigger**: Two processes attempt refresh simultaneously; second one reuses already-consumed token.

**Error**: Provider returns `invalid_grant` or `refresh_token_reused` from /oauth/token endpoint

**oauth-mux broker response**:
- Detects via credential/refresh error analysis
- Marks account as `auth_unready` (requires manual re-enrollment)
- Does not swap (can't fix via muxing)
- Raises `refresh_failed` error with typed reason
- Operator must enroll account again (full OAuth code flow)

**Prevention**: Broker holds per-account mutex during RefreshToken; re-reads auth.json under lock to detect if another process already consumed the token.

### 7.4 Refresh Token Expired

**Trigger**: Token past provider's expiration window (typically months; provider-specific).

**Error**: Provider returns `invalid_grant` from /oauth/token endpoint

**oauth-mux broker response**:
- Detects via error analysis
- Marks account as `auth_unready`
- Raises credential/refresh error with reason `refresh_token_expired`
- Operator must re-enroll account

---

## 8. Configuration and Environment Variables

### 8.1 Codex Environment Variables

| Var | Purpose | Set by | Example |
|-----|---------|--------|---------|
| CODEX_HOME | Auth/config home | User or shim | ~/.codex |
| CODEX_SQLITE_HOME | Session DB home | oauth-mux (managed) | ~/.codex |
| CODEX_AUTH_FILE | Wrapper-local variable observed on neo; native Codex support unproven | Home Manager wrapper | ~/.codex/auth.json |
| CODEX_SESSION_HOME | Session files home | Managed flag | ~/.codex or <custom> |

### 8.2 oauth-mux Managed Codex Variables

| Var | Purpose | Example |
|-----|---------|---------|
| OMUX_CODEX_BIN | Native Codex binary path | /nix/store/.../bin/codex |
| OMUX_CODEX_SHIM | Set to 1 by shim during managed entry | 1 |
| OMUX_CODEX_CONFIG_HOME | Override config home discovery | ~/.codex or <custom> |
| OMUX_CODEX_SESSION_HOME | Override session home | ~/.codex or <custom> |
| OMUX_CODEX_STRICT_SQLITE_LOCK_GUARD | Fail if SQLite lock held (diagnostic) | 0 or 1 |

---

## 9. Verification and Diagnostic Outputs

### 9.1 `codex doctor` Output

Key fields for oauth-mux engineers:

```
Auth
  ✓ auth is configured
      auth storage mode        File
      auth file                ~/.codex/auth.json
      stored auth mode         chatgpt
      stored API key           false
      stored ChatGPT tokens    true
      
State
  ✓ state databases healthy
      CODEX_HOME               ~/.codex (dir)
      sqlite home              ~/.codex (dir)
      state DB                 ~/.codex/state_5.sqlite (file) · integrity ok
      log DB                   ~/.codex/logs_2.sqlite (file) · integrity ok
```

Confirm:
- `stored auth mode: chatgpt` (not openai_api_key)
- `stored ChatGPT tokens: true` (access_token, id_token, refresh_token present)
- SQLite DB files exist and pass integrity check

### 9.2 Session Status Artifacts

**oauth-mux managed session status** (JSON):

```json
{
  "mode": "codex_broker_owned_session_live_run",
  "claim": {
    "level": "broker_owned_app_server",
    "broker_owned_session": true,
    "current_process_auth_broker": false
  },
  "auth": {
    "mode": "chatgpt",
    "tokens_present": true,
    "refresh_triggered": false
  },
  "quota": {
    "observed": false,
    "evidence": null
  },
  "session": {
    "selected_account": "codex:max-1",
    "selected_capability": "codex-max",
    "fallback_ready": true,
    "home_type": "canonical_bridge"
  }
}
```

**On auth writeback** (post-exit):
```json
{
  "event": "auth_writeback",
  "account": "<redacted>",
  "changed": true,
  "written": true,
  "source_conflict": false
}
```

Never print token material, file paths, or full account IDs in status output.

---

## 10. Summary for oauth-mux Engineers

### Key Takeaways

1. **auth.json is single-source of truth** for Codex: read/write by Codex process, imported post-exit by oauth-mux. Keys: access_token (wire auth), id_token (claims), refresh_token (renewal).

2. **refresh_token is single-use**: Each successful refresh consumes it. oauth-mux broker serialization is the intended mitigation against reuse races (OAuth 2.1 §4.3.1); verify the live code path before relying on this draft as canonical.

3. **Session state authority is the product boundary**: canonical-bridge mode stores state_5.sqlite and logs_2.sqlite in canonical ~/.codex through managed homes. The 2026-06-02 TIN-1851 investigation found that this model is fragile unless the managed home is durable and path-stable. The safer candidate default is home-is-store / isolated persistent account homes, where muxed Codex sessions never write canonical ~/.codex.

4. **Quota is per-account, per-period**: 429 usage_limit_reached includes plan_type (SKU) and resets_at (reset time). oauth-mux swaps accounts if fallback available; otherwise returns error to Codex.

5. **Entitlement (plan_type) is SKU, not rate**: A free account cannot use Codex (usage_not_included); no amount of swapping fixes that. pro account can use Codex but may hit weekly quota exhaustion.

6. **Bearer tokens are wire-portable**: No DPoP/cnf claims; access_token moves across processes. oauth-mux can substitute Authorization and ChatGPT-Account-ID headers per request.

7. **Sticky routing token (x-codex-turn-state) must be dropped on swap**: Keeping it when switching accounts risks session state pinning to the wrong account upstream.

8. **Managed homes must be durable when they can appear in Codex state**: overlays created under ~/.oauth-mux/managed-codex-homes/ improve on disposable `$TMPDIR` homes because recorded rollout paths remain resolvable after scrub. The stronger TIN-1851 home-is-store branch removes canonical sqlite bridging for muxed sessions entirely and should be treated as the trustable architecture candidate until live e2e proves otherwise.
