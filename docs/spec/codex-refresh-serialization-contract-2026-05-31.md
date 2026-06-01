# Codex Refresh Serialization & Adapter-Agnostic Re-Login — Design Contract

Status: **Draft design (2026-05-31). Implementation pending (TIN-1591); the acceptance tests do not exist yet — they are the gate to land alongside the fix.**
Owner: oauth-mux
Incident anchor: `docs/incidents/2026-05-31-codex-refresh-token-race.md` (host `neo`, 10+ parallel Codex sessions → `token_revoked` / "refresh token already used")
Upstream class: `openai/codex#10332` (incident signature); `openai/codex#9634` (cited by `docs/spec/broker-mcp-contract-2026-05-03.md:283`, `docs/spec/codex-adapter-contract-2026-05-03.md:501`)

> **Scope boundary (never-halt):** refresh serialization fixes the token-rotation
> *race*. It does **not** by itself deliver Level-3 `next_turn_seamless`
> ("account A exhausts and account B continues"). The 2026-05-31 brick proved a
> second, independent gap: the route selector is capability-scoped and will not
> degrade `codex-max → codex-mini` (or wait out quota) when a capability
> saturates — it halts with `NoAccountSelectable` even when a live route exists.
> That cross-capability degradation is tracked separately as **GH #339 / TIN-1811**
> (omux Foundations · resilience-never-halt). A dead/exhausted account must never
> halt work; one live route is enough.

---

## 1. Context & Problem

### 1.1 The race class, precisely

OAuth refresh tokens are single-use/rotating: a successful refresh invalidates the
refresh token it consumed and returns a new one. Critical section in
`refreshCodexAccountAuthFile` (`src/broker_loader.zig:362-390`):

1. `readFileAlloc(path)` — read current `refresh_token` (`:372`).
2. `parseCodexAuthRefreshMaterial` — extract it (`:375-377`).
3. `oauth.refreshToken(...)` — network POST to `def.auth.token_endpoint` (`:380`;
   codex = `https://auth.openai.com/oauth/token`, `src/provider_schema.zig:721`)
   that **rotates/invalidates** the supplied refresh token server-side
   (`src/oauth.zig:18`).
4. `buildRefreshedCodexAuthJson` → `writeFileReplace(path, …)` (`:385-387`).

No lock is held across `:372 → :387`. Two processes whose access-token `exp` both
crossed the `exp - 300` boundary (`refreshCodexAuthState`, `:398-404`, `:426-428`)
read the same `refresh_token` at `:372` and each POST it at `:381`. OpenAI accepts
the first (rotates) and returns 401 `token_revoked` to the rest.

`writeFileReplace` (`:552-580`) writes to `path.tmp-<rand>` with `.exclusive=true`
(O_EXCL on the unique tmp name only), `fsync`, then `rename`. That guarantees
**write atomicity** (no torn file, last-writer-wins byte image) — it is **not** a
refresh mutex. The contended resource is the network POST at `:381`.

The materializer is invoked **per outbound request**
(`src/adapters/codex/wire_proxy.zig:562`), so the window is hit repeatedly across
the session fleet. The same `refreshCodexAccountAuthFile` is also called by the
preflight sweep `repairRefreshableCodexAuthFailures` (`:107`, call `:138`).

> **Routing note.** The proxy's *upstream* is `chatgpt.com`
> (`wire_proxy.zig:73-75`), so request errors read `chatgpt.com/backend-api/codex/responses`
> even when fully brokered — that does **not** prove direct mode. The *refresh*
> POST that rotates the token is a separate endpoint (`auth.openai.com/oauth/token`).

### 1.2 Why oauth-mux can amplify it

oauth-mux uses **per-session in-process proxies, no shared daemon**
(`README.md:257`; per-session proxy+materializer bind at
`src/adapters/codex/main.zig:1247-1257`). N concurrent `oauth-mux codex`
invocations = N independent OS processes, each with its own materializer, all
pointed at the same per-account `auth.json`, with no `flock`/`O_EXCL`/mutex around
the read → refresh → write path. Additionally, `shouldPreserveChildAuth`
(`wire_proxy.zig:1645-1654`) lets the Codex child forward and rotate the shared
token out-of-band (`:584-589`), a second uncoordinated writer.

### 1.3 The spec/reality gap — and the in-tree primitive

The specs already *promise* a per-account refresh mutex (broker-contract §2.3,
codex-adapter-contract §7.2, citing `openai/codex#9634`), but a repo-wide search
finds **zero** `flock`/`O_EXCL`/`LOCK_EX`/`fcntl`/cross-process `Mutex` in
`src/oauth.zig` or the refresh path of `src/broker_loader.zig`. The in-process
`std.Thread.Mutex` (`src/main.zig:14421`, `:14617`) is useless across processes.

The locking primitive **already ships in-tree**: `repair_state.acquireRepairLock`
(`src/repair_state.zig:362-397`) — a per-account exclusive file lock keyed
`provider:account`, with path helpers (`lockPath`/`sanitizedLockFileName`/
`ensureParentDir`, `:438-454`). It is wired only to interactive repair
(`src/main.zig:2897,5168`, `src/runtime.zig:156`), never to the silent
`exp - 300` refresh. The fix applies the existing idiom to the refresh path.

### 1.4 Out of scope (lab-owned)

The 2026-05-31 incident was compounded by a home-manager `sops-nix` mechanism that
materialized a stale `~/.codex/auth.json` over the live token on every switch
(disabled at the lab layer). Not an oauth-mux defect; the race below reproduces
independently.

---

## 2. Goals / Non-Goals

**Goals**

1. Eliminate the double-spend of single-use refresh tokens across concurrent
   oauth-mux processes (and threads), collapsing N concurrent refreshes into
   **1 POST + (N-1) no-ops**.
2. Keep the fix **below the adapter** (keyed on `provider:account` + store path),
   so single-harness multi-session benefits too.
3. Close the child-rotation channel so the Codex child cannot rotate the shared
   token out from under oauth-mux.
4. Provide an **adapter-agnostic serial re-login** surface (enrollment / callback /
   web UI + CLI) for the revoked-token case, serialized on the same domain.
5. Ship **provable, test-verifiable, search-discoverable** evidence: a
   deterministic, no-spend repro that fails today and passes after the fix,
   emitting the literal incident strings.

**Non-Goals**

- A mandatory shared broker daemon (stays optional; correctness must not depend on
  it; `README.md:257`, broker-contract `daemon_hosts_broker:false`).
- Fixing the lab sops-nix materialization (lab-owned, already disabled).
- Silent browser/device login without operator consent
  (`docs/spec/in-agent-reauth-handoff-contract-2026-05-14.md` §1/§7).

---

## 3. Design A — Cross-Process Refresh Serialization (the OAuth semaphore)

### 3.1 Approach comparison

| | (1) Advisory per-account file lock + double-checked re-read | (2) Shared broker daemon owns refresh | (3) Hand-rolled "in-progress" sentinel |
|---|---|---|---|
| Cross-process correct | Yes (kernel `flock`, OS-arbitrated) | Yes | Yes |
| Matches per-session/no-daemon arch | Yes — drop-in | No — new always-on service/socket/lifecycle | Yes |
| Reuses in-tree code | Yes — `acquireRepairLock` idiom, same key | No | Partial |
| Avoids double-refresh | Yes (re-read under lock) | Yes (single owner) | Yes |
| Crash / stale-lock safety | High — `flock` released on fd close/death; no sentinel to GC | Daemon crash = outage | Lower — SIGKILL orphans sentinel; needs TTL/PID reaping |
| Blast radius / LOC | Smallest | Largest | Medium |

### 3.2 Recommendation: Approach (1)

Advisory per-account exclusive file lock (blocking for the silent refresh waiter)
with a **double-checked re-read** under the lock. Rationale: no architectural
change; the primitive/key/path/parent-dir-creation already exist and are tested in
`src/repair_state.zig:362-454`; kernel `flock` auto-releases on process death (no
stale-lock GC — the decisive edge over (3)); "wait & re-read" falls out for free.
Approach (2) is the right *long-term* shape only if oauth-mux grows a real broker
daemon; out of scope here.

### 3.3 Lock semantics

- **Key domain:** `provider:account` (matching `repair_state.lockPath`), not
  per-session, not per-overlay-path. Guarded state = the per-account `auth.json`.
- **Lock location:** reuse the **repair-lock domain** so refresh and interactive
  repair are mutually exclusive (a session cannot silently refresh while a repair
  re-login is mid-flight). A sibling `auth-locks/<provider>-<account>.lock` under
  `runtimeDir` is acceptable if a distinct domain is preferred.
- **Acquisition mode:** silent refresh waiter uses **blocking**
  (`lock_nonblocking = false`) with a **bounded wait** (~10s → degrade to
  `SecretUnavailable` rather than hang). Interactive repair keeps the existing
  `lock_nonblocking = true` / fail-fast `RepairInProgress` semantics.
- **Double-checked locking:** after acquiring, re-`readFileAlloc` and re-run
  `refreshCodexAuthState` (`:398-404`). If `exp > now + 300` → `.not_needed` →
  return without POSTing. Collapses N→1 and guarantees POSTing the *current* token.

### 3.4 Exact change points

**Change 1 (PRIMARY) — `src/broker_loader.zig`.** Wrap the critical section in
`refreshCodexAccountAuthFile` (`:362-390`): acquire a blocking exclusive
per-account lock before the read at `:372`, hold through `writeFileReplace` at
`:387`. After acquiring, re-read and re-evaluate `refreshCodexAuthState`; if a
peer already rotated, return (no-op).

```zig
fn refreshCodexAccountAuthFile(allocator, cfg, provider, account, acct_cfg) !void {
    // NEW: blocking exclusive per-account lock (key = provider:account), bounded wait.
    var lock = try acquireAccountAuthLock(allocator, provider, account, .blocking);
    defer lock.deinit();

    const path = try accountAuthMaterialPath(allocator, acct_cfg);
    defer allocator.free(path);

    // NEW: double-checked locking — re-read & re-evaluate under the lock.
    const bytes = try readFileAlloc(allocator, path);
    defer allocator.free(bytes);
    if (refreshCodexAuthState(allocator, bytes) != .needed) return; // peer rotated → no-op

    // ... unchanged :375-387: parse, token_url, oauth.refreshToken, build, writeFileReplace ...
}
```

- `acquireAccountAuthLock` is a ~15-line clone of `acquireRepairLock`
  (`src/repair_state.zig:362-397`) with `lock_nonblocking = false` + bounded retry,
  reusing `lockPath`/`sanitizedLockFileName`/`ensureParentDir` (`:438-454`). Add it
  beside `acquireRepairLock` so refresh and repair share one domain.
- Both callers inherit the lock with no change: `refreshCodexAuthBeforeMaterialize`
  (`:421`) and the preflight sweep `repairRefreshableCodexAuthFailures` (`:138`).
- The outer `materializeChatgpt` (`:683-694`) need not also lock; its re-read at
  `:688` observes the rotated file once Change 1 lands.

**Change 2 (SECONDARY) — `src/adapters/codex/wire_proxy.zig`.** Change 1 alone
leaves the Codex child as a second uncoordinated writer. For accounts oauth-mux
owns (`acct_cfg.config_dir != null` — the predicate already gating refresh at
`broker_loader.zig:122,415`), add a guard at the top of `shouldPreserveChildAuth`
(`:1645-1654`) returning `false`. The child then always receives the
broker-substituted token (`:1637-1638`) and never rotates the shared token;
oauth-mux is the sole refresher. Unmanaged default-store accounts
(`config_dir == null`, `broker_loader.zig:120-122`) keep child-refresh behavior.

### 3.5 Crash-safety, staleness, Darwin

- **Crash-safety:** `flock` releases on fd close and process death (SIGKILL
  included). The lock *file* may persist but the *lock* does not — strictly safer
  than a hand-rolled sentinel.
- **Staleness:** the re-read inside the lock POSTs only the current token.
- **Darwin:** Zig `std.fs.File` `.lock = .exclusive` → `flock(LOCK_EX)`, supported
  on local APFS/HFS+ (store under `~/.local/share` / `XDG_DATA_HOME`). Advisory,
  whole-file, auto-released; no `fcntl` byte-range subtleties. Already exercised on
  this platform by `repair_state` and `src/trace.zig:187-193`.
- **Validate during implementation:** the unit test (§5.1) relies on `flock`
  contending across independent open-file-descriptions **within one process**
  (threads). This is the expected POSIX semantic but is a property of the chosen
  primitive — confirm it on the target platform rather than assuming.

---

## 4. Design B — Adapter-Agnostic Enrollment / Callback / Serial Re-Login

### 4.1 Where this sits

Design A serializes the *silent* refresh. Design B is the *interactive* sibling:
when refresh is impossible (`token_revoked` / 401), an operator/harness performs a
fresh provider login. That re-login serializes on the **same `provider:account`
lock**, so N concurrent revocations produce exactly **one** login flow and (N-1)
waiters that re-read the freshly written store. It is bounded by the consent
contract (`in-agent-reauth-handoff-contract-2026-05-14.md:18-21`): oauth-mux MUST
NOT silently run browser/device login. The web UI / callback is an
operator-facing, user-mediated surface that lowers activation cost and serializes
the existing `oauth-mux codex login-device` handoff.

### 4.2 Adapter-agnostic interface

oauth-mux already has a provider-neutral account/secret model (`src/config.zig`),
a declarative `ProviderDefinition` (`src/provider_schema.zig:31-77,231-241`), and a
neutral store-path resolver (`src/paths.zig`). The Codex-hardcoded parts are
`broker_loader.materializeChatgpt` (`:641-695`) and the `ProviderKind` switches in
`src/provider.zig`. Add a small Zig vtable capturing exactly what re-login needs —
new file `src/enroll/reauth_adapter.zig`:

```zig
pub const ReauthAdapter = struct {
    provider: []const u8,            // "codex", "claude", "figma", ...
    flow: LoginFlow,
    vtable: *const VTable,

    pub const LoginFlow = enum {
        device_code,       // codex login --device-auth (poll; no loopback)
        redirect_loopback, // OAuth authz-code + PKCE → http://127.0.0.1:<port>/callback
        command_owned,     // claude auth login (CLI owns the flow; we isolate the dir)
        pat_paste,         // figma PAT paste (no OAuth)
    };

    pub const VTable = struct {
        storePath:         *const fn (Ctx, Alloc, account: []const u8) anyerror![]u8,
        loginHandoff:      *const fn (Ctx, Alloc, account: []const u8) anyerror!Handoff, // argv+env, never auto-run
        buildAuthorizeUrl: ?*const fn (Ctx, Alloc, redirect_uri: []const u8, pkce: Pkce) anyerror![]u8 = null,
        exchangeCode:      ?*const fn (Ctx, Alloc, code: []const u8, pkce: Pkce, redirect_uri: []const u8) anyerror!CredentialBytes = null,
        writeStore:        *const fn (Ctx, Alloc, account: []const u8, cred: CredentialBytes) anyerror!void, // → writeFileReplace, lock held
        livenessSummary:   *const fn (Ctx, Alloc, account: []const u8) anyerror!Liveness, // no-spend, redacted
    };
};
```

`buildAuthorizeUrl`/`exchangeCode` are **optional** — only `redirect_loopback`
adapters implement them. Codex is `device_code` (`src/main.zig:8565-8584`) and
needs no loopback; its proven flow is untouched. Registration is a comptime table
parallel to `provider_schema.builtin_providers` (`:231-241`), new file
`src/enroll/reauth_registry.zig`.

### 4.3 Serialized re-login queue / semaphore

Add to `src/repair_state.zig` a single primitive used by **both** silent refresh
(Design A, NONBLOCKING) and interactive reauth (Design B, BLOCKING):

```zig
pub fn acquireAccountAuthLock(alloc, provider, account, mode: enum { nonblocking, blocking }) !AuthLock
```

Body is the existing `createFileAbsolute(..., .lock = .exclusive,
.lock_nonblocking = (mode == .nonblocking))` (`:371-379`) with `lockPath` keyed
`<provider>-<account>.lock` (`:438-444`). One lock for refresh AND reauth: a
revoked-token reauth writing a brand-new `auth.json` must not race a peer
mid-silent-refresh.

Single-flight via double-checked liveness (the interactive analogue of §3.3):

```
acquireAccountAuthLock(provider, account, .blocking)   // wait my turn
defer lock.release()
cred = readStore(account)                              // re-read AFTER lock
if livenessSummary(cred) == .live: return .already_repaired_by_peer  // (K-1) waiters exit here
// else: I am the elected re-login driver
run interactive login flow (device | redirect | command | pat)
writeStore(account, new_cred)                          // atomic, lock held
```

For the daemon/web-UI case (single long-lived process), add a per-`provider:account`
in-process `std.Thread.Mutex` *plus* the on-disk lock (so UI and a stray CLI
session still serialize), with a per-account `ReauthJob` state machine
single-flighted by an in-process map. New file `src/enroll/reauth_queue.zig`.

### 4.4 Loopback callback handler (redirect_loopback only)

New file `src/enroll/callback_server.zig`:

```
bind loopback 127.0.0.1:0 (ephemeral port); redirect_uri = http://127.0.0.1:<port>/callback
state = random 32B; pkce = S256(verifier); authorize_url = adapter.buildAuthorizeUrl(...)
→ hand authorize_url to operator (print/open)   [MEDIATED, not auto-opened by default]
serve exactly ONE /callback:
    validate state (CSRF) else 400; extract code
    cred = adapter.exchangeCode(code, pkce, redirect_uri)
    --- LOCK BOUNDARY (same provider:account auth lock, held by the ReauthJob) ---
    adapter.writeStore(account, cred)   // broker_loader.writeFileReplace, atomic
    respond 200 "You may close this tab."; signal ReauthJob complete
```

Properties: loopback-only, ephemeral port, one-shot; `state` + PKCE mandatory; the
`writeStore` happens while the account lock is held (acquired by the owning
`ReauthJob` before the listener opens), so a concurrent silent refresh cannot
interleave with the reauth publish. Codex needs no callback server (device flow
polls; `codex login --device-auth` writes `auth.json`, then the `ReauthJob`
re-reads/validates under lock).

### 4.5 `ReauthJob` state machine

```
revocation → detected (token_revoked / refresh-already-used / 401)
  → queued (waiting on acquireAccountAuthLock(.blocking))
  → rechecking_liveness (re-read under lock)
        ├─ live → repaired (peer fixed it; release lock)
        └─ dead → awaiting_consent (show handoff / authorize_url)
             → login_in_flight (device poll | loopback callback | CLI)
             → writing (writeStore under lock, atomic)
             → verifying (livenessSummary, no-spend)
                  ├─ live → repaired
                  └─ not-live → failed(reason)
```

`awaiting_consent`/`login_in_flight` carry a TTL (~300s); on timeout the lock
releases and the job goes `failed(timeout)` so a walked-away operator cannot hold
the account lock forever. State labels are redaction-safe.

### 4.6 Minimal web UI + CLI equivalent

**Web UI** — a tiny `127.0.0.1`-only server-rendered surface (static HTML + thin
JSON API), `src/enroll/web_ui.zig`, started by `oauth-mux reauth ui`:

| Route | Purpose | Backed by |
|---|---|---|
| `GET /` | Account list + per-account liveness + **Re-login** button on rows needing action | `accounts list --json` + `routeReadiness` (`runtime.zig:145-161`) |
| `POST /reauth/{provider}/{account}` | Enqueue a `ReauthJob` (single-flight); returns job id + state | `reauth_queue` |
| `GET /reauth/{provider}/{account}` | Poll job state | `ReauthJob` |
| `GET /callback` | OAuth loopback target (redirect_loopback only) | `callback_server` |
| `GET /healthz` | UI liveness | — |

Clicking **Re-login** on an account whose job already exists **joins** it
(single-flight is the UI manifestation of serialization). The human always
completes the upstream login.

**Headless / CLI equivalent** — same state machine, no HTTP, under the existing
dispatch (`src/cli.zig`):

```bash
oauth-mux accounts list --json
oauth-mux reauth start --provider codex --account max-1 --json   # serialized re-login (blocks on lock, double-checks)
oauth-mux reauth wait  --provider codex --account max-1 --timeout 300 --json
oauth-mux reauth drain --provider codex --json                   # batch, serialized one account at a time
```

### 4.7 Integration with preflight / route / health and OMUX_*

- `routeReadiness` already returns `.repair_in_progress` when `probeRepairLock`
  sees a held lock (`src/runtime.zig:156-158`). Extend the probe to recognize the
  account-auth lock, so while a `ReauthJob` holds it, `doctor runtime` /
  `route explain` / `codex preflight` report `reauth_in_progress` and other
  sessions wait rather than stampede.
- `codex preflight` already splits `agent_safe` / `user_mediated` /
  `spend_confirmed` next-actions; re-login slots into `user_mediated_next_actions`
  as the existing `oauth-mux codex login-device <account>` handoff, optionally
  annotated with `reauth_job_id` / `reauth_ui_url`.
- Add provider-neutral env keys parallel to the existing `OMUX_*` child env
  (`src/adapters/codex/main.zig:1403-1409`): `OMUX_REAUTH_UI_URL`,
  `OMUX_REAUTH_LOCK_DIR`, `OMUX_REAUTH_JOB`. The `OMUX_CODEX_*` namespace is
  untouched.
- When the optional daemon runs it hosts `reauth_queue` + the web UI for
  cross-session single-flight; absent it, the on-disk `flock` still serializes —
  the daemon is an optimization, not a correctness dependency.

---

## 5. Test & Verification Plan (all no-spend; to be implemented with the fix)

> The unit/smoke artifacts below **do not exist yet**; they are the acceptance
> gate to land alongside the fix. Two correctness facts drive their shape:
> (1) the refresh POST hits the **token endpoint** (`auth.openai.com/oauth/token`),
> stubbed by overriding the provider def `token_endpoint` — the seam the existing
> test `src/broker_loader.zig:936-990` uses (`"token_endpoint": "://invalid"` at
> `:959`) — **not** the `chatgpt.com` responses upstream
> (`scripts/test-stub-upstream.py`); and (2) `oauth.refreshToken` discards the
> response body and returns only `error.RefreshDenied` (`src/oauth.zig:55-57`), so
> the literal incident strings must be emitted by the **test/stub print lines and
> the stub's 401 body**, not assumed to flow through oauth-mux output.

### 5.1 Unit test (primary proof) — beside `src/broker_loader.zig:865-1014`

In-process stub **token endpoint** (no network) holding `consumed: ?[]const u8`.
On `grant_type=refresh_token`: token == current & unconsumed → mark consumed,
rotate, **200** with rotated token; already consumed → **401** body
`{"error":"token_revoked","error_description":"Your access token could not be refreshed because your refresh token was already used. Please log out and sign in again."}`.

Seed one `auth.json` with an **expired** access JWT (`exp <= now + 300`) and a
known `refresh_token`; point the codex provider def `token_endpoint` at the stub;
spawn **N=8** threads each calling `refreshCodexAccountAuthFile`.

```
# reproduces TODAY (lock absent): assert revoked_count >= 1 && stub.post_count > 1
REFRESH-RACE-REPRO: detected token_revoked
REFRESH-RACE-REPRO: upstream said "refresh token already used. Please log out and sign in again."
REFRESH-RACE-REPRO: server refresh_token POST count = 8 (expected 1 under serialization)

# passes WITH serialization: assert stub.post_count == 1 && revoked_count == 0
REFRESH-RACE-FIXED: 8 concurrent refreshers, 1 token-endpoint POST, 0 token_revoked
REFRESH-RACE-FIXED: serialized via per-account flock (provider:account)
REFRESH-RACE-FIXED: all 8 sessions converged on one rotated refresh_token
```

Test name carries the searchable strings. Run: `just test` → `zig build test`
(`build.zig:31-38`).

### 5.2 No-spend cross-process smoke — `scripts/smoke-codex-refresh-race.sh`, `just smoke-codex-refresh-race`

Reuse the closest existing assets:
- `scripts/smoke-codex-cassette-replay.sh:246-248` already does
  `POST /oauth/token → 401` (`redacted_refresh_reused`) — the working pattern for
  stubbing the **token endpoint**.
- `scripts/smoke-codex-concurrent-sessions.sh` is the concurrency harness but uses
  **distinct** accounts; the new smoke points **both** session entries at **one
  shared** account store and seeds it with an **expired** access JWT so
  `refreshCodexAuthState == .needed`.
- A **token-endpoint** stub with a stateful "revoke after first refresh" mode
  returning a `token_revoked` body (the existing `scripts/test-stub-upstream.py`
  can force 401 via `OMUX_STUB_ALWAYS_STATUS`/`OMUX_STUB_ACCOUNT_STATUS_JSON` but
  is the `/responses` upstream and lacks a `token_revoked` body — it is **not** the
  endpoint to stub here).

- **Failing variant** (lock off): token-endpoint stub log shows ≥2 refresh POSTs of
  the same token; ≥1 session emits `token_revoked`. Terminal:
  `refresh-race smoke: REPRODUCED token_revoked double-spend (N refresh POSTs > 1).`
- **Passing variant** (lock on): exactly 1 refresh POST; both sessions succeed;
  `jq -r '.tokens.refresh_token'` shows one rotated token; zero `token_revoked`.
  Terminal: `all <k> assertions passed.`

### 5.3 Design B acceptance tests

- `reauth_queue` unit: two threads `enqueue(codex, max-1)` → exactly one reaches
  `login_in_flight`, the other resolves `already_repaired_by_peer`.
- `repair_state` unit: A holds `acquireAccountAuthLock(.blocking)`; B's
  `.nonblocking` returns the in-progress error; B's `.blocking` resolves only after
  A releases.
- `callback_server` unit: bad `state` → 400, no `writeStore`; good `state`+`code` →
  `writeStore` called once, file replaced atomically (temp dir via
  `OMUX_REAUTH_LOCK_DIR`).
- `just smoke-codex-reauth-serialized`: two sessions on one account; token-endpoint
  stub returns 401 after first refresh. Failing baseline asserts the second session
  emits `token_revoked`; passing runs `oauth-mux reauth start` (device login stubbed)
  and asserts both sessions serialize on one fresh token.

### 5.4 Why these exact strings

`token_revoked`; `Your access token could not be refreshed because your refresh
token was already used. Please log out and sign in again.`; `already used. Please
log out and sign in again.`; URL `https://chatgpt.com/backend-api/codex/responses(/compact)`
— appear in unit markers, smoke assertions, test names, the incident doc, and the
README "Known failure" subsection. Anyone searching those errors (and
`openai/codex#10332` / `#9634`) lands on this repo and its committed proof.

---

## 6. Rollout / Migration

1. **Design A behind a default-ON flag.** Implement `acquireAccountAuthLock` in
   `repair_state.zig`; wrap `refreshCodexAccountAuthFile`. Gate the lock on
   `OMUX_REFRESH_LOCK` (default `on`) **only** so the failing repro variant can
   disable it; production never runs `off`. Ship the §5.1 unit test in the same
   change.
2. **Change 2 (`shouldPreserveChildAuth`) immediately after**, gated on
   `config_dir != null`; verify with the same-account child-refresh smoke
   (`scripts/smoke-codex-child-refresh.sh`) extended to assert the child no longer
   rotates the managed-store token.
3. **Discoverability docs in the same PR(s):** a "Known failure" subsection in
   `README.md` (under "Still research or open") carrying the literal error strings
   + `openai/codex#10332`/`#9634`; this contract doc cross-linked from
   `docs/README.md` (Specs) and the incident doc
   (`docs/incidents/2026-05-31-codex-refresh-token-race.md`). File the GitHub issue
   separately so the strings are indexed.
4. **Design B incrementally, additively** (no behavior change until verbs are
   invoked): (a) share `acquireAccountAuthLock`; teach `routeReadiness` to probe
   the account-auth lock; (b) `src/enroll/` package
   (`reauth_adapter.zig`, `reauth_registry.zig`, `reauth_queue.zig`,
   `codex_reauth.zig`); (c) CLI verbs `reauth {start,wait,drain}` + `OMUX_REAUTH_*`
   env; (d) `callback_server.zig` + `web_ui.zig` + `reauth ui` last.
5. **Migration:** no on-disk `auth.json` format change; new lockfiles auto-created/
   auto-released; unmanaged default-store accounts unchanged; daemon optional. Roll
   out per-host; the lock is local to each host's account store.

---

### File:line index for implementers

- `src/broker_loader.zig:362-390` `refreshCodexAccountAuthFile` — PRIMARY lock site.
- `src/broker_loader.zig:398-404,426-428` `refreshCodexAuthState` — `exp<=now+300`.
- `src/broker_loader.zig:406-424` `refreshCodexAuthBeforeMaterialize` (`:415`
  `config_dir`; `:421` caller).
- `src/broker_loader.zig:107`/`:138` `repairRefreshableCodexAuthFailures` — preflight sweep, inherits lock.
- `src/broker_loader.zig:552-580` `writeFileReplace` — atomic publish; stays inside lock.
- `src/broker_loader.zig:641-695` `materializeChatgpt` — read `:683`/refresh `:687`/re-read `:688`.
- `src/broker_loader.zig:936-990` existing token-endpoint override test seam (`:959`).
- `src/oauth.zig:18` `refreshToken` (`:55-57` discards body → `error.RefreshDenied`); token URL via `def.auth.token_endpoint`.
- `src/provider_schema.zig:83` `token_endpoint` field; `:721` codex `auth.openai.com/oauth/token`.
- `src/repair_state.zig:362-397` `acquireRepairLock` + `:438-454` path helpers; `:399-418` `probeRepairLock`.
- `src/adapters/codex/wire_proxy.zig:1645-1654` `shouldPreserveChildAuth` / `:1616-1643` `setOutboundAuthHeaders` (`:1627-1628` forward-child vs `:1637-1638` substitute); `:73-75` upstream host; `:562` per-request materialize; `:584-589` `proxy_preserved_child_auth`.
- `src/adapters/codex/main.zig:1247-1257` per-session proxy bind; `:1403-1409` child env; `:8565-8584` device-login dispatch.
- `src/main.zig:16591-16608` `codexStoreRoot`/`codexAccountDir`; `:2897,5168` repair-lock callers; `:14421,14617` in-process mutex.
- `src/runtime.zig:145-161` `routeReadiness` (`:156-158` lock probe).
- `src/cli.zig` enroll/codex dispatch (add `reauth` verbs); `src/paths.zig` path/runtime dirs.
- `build.zig:31-38` `zig build test`.
- `scripts/smoke-codex-concurrent-sessions.sh`, `scripts/smoke-codex-child-refresh.sh`, `scripts/smoke-codex-cassette-replay.sh:246-248`, `scripts/test-stub-upstream.py:98-160`.
- Specs: `broker-mcp-contract-2026-05-03.md` §1.2/§2.3 (`:283`); `codex-adapter-contract-2026-05-03.md` §7.2 (`:501`); `in-agent-reauth-handoff-contract-2026-05-14.md`; `account-enrollment-agent-contract-2026-05-01.md`; `future-adapter-roadmap-2026-05-10.md`.
