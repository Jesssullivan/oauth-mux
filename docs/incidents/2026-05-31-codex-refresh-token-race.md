# Concurrent Codex sessions double-spend single-use OAuth refresh tokens → `token_revoked` / "refresh token already used"

> This file is the canonical write-up. It is also the body for the GitHub issue
> of the same name, kept in-repo so the failure signature is committed, diffable,
> and search-indexed alongside the fix.

**Labels:** `bug` · `oauth` · `auth` · `refresh-token` · `token-rotation` ·
`concurrency` · `race-condition` · `mutex` · `serialization` · `codex` ·
`chatgpt` · `token_revoked` · `multi-session` · `enterprise`

**Search keywords:** refresh token already used · token_revoked · refresh token
rotation race · concurrent Codex sessions · "Please log out and sign in again" ·
single-use refresh token · OAuth double-spend · parallel agent sessions ·
`chatgpt.com/backend-api/codex/responses` 401 · multi-process refresh lock ·
`openai/codex#10332` · `openai/codex#9634`

---

## TL;DR

If you run **multiple concurrent Codex / ChatGPT sessions that share one OAuth
account** and you see any of:

```
Your access token could not be refreshed because your refresh token was already used. Please log out and sign in again.
token_revoked
HTTP 401  POST https://chatgpt.com/backend-api/codex/responses
HTTP 401  POST https://chatgpt.com/backend-api/codex/responses/compact
already used. Please log out and sign in again.
```

…this is a **rotating (single-use) OAuth refresh-token double-spend race**. Two
or more processes read the same `refresh_token`, each POSTs it to the OAuth token
endpoint, the server rotates on the first and **revokes** the rest. It is the
same upstream failure class as **`openai/codex#10332`** (oauth-mux's own specs
track the class as `openai/codex#9634`).

`oauth-mux` treats this as an **OAuth mutual-exclusion / semaphore serialization
concern it intends to own**, because it breaks enterprise agent-laced harness
workflows even for a single harness fanning out multiple sessions. This issue
documents the behavior, a **provable, test-verifiable reproduction**, and the
fix.

> **The error URL does not prove direct/native mode.** The
> `chatgpt.com/backend-api/codex/responses` URL appears because `oauth-mux`
> **proxies upstream to `chatgpt.com`** (`src/adapters/codex/wire_proxy.zig:73-75`).
> Routing through the broker produces the same upstream URL. What matters is the
> refresh-token rotation race, not the URL. Note also that the *refresh* POST
> that actually rotates the token goes to a **different** endpoint — the OAuth
> token endpoint `https://auth.openai.com/oauth/token`
> (`src/provider_schema.zig:721`), not `chatgpt.com`.

---

## Expected vs Actual

**Expected:** N concurrent sessions sharing one OAuth account perform **at most
one** refresh-token rotation. The first refresh rotates the token; every other
session observes the freshly rotated token (or waits for the in-flight refresh)
and continues. No session is revoked.

**Actual:** N concurrent sessions each independently detect the access token is
near expiry, each read the **same** `refresh_token` from the shared `auth.json`,
and each POST it to the OAuth token endpoint. The server accepts the **first**
(rotating/invalidating that refresh token) and returns `token_revoked` / HTTP 401
/ "refresh token already used" to the **rest**. Affected sessions die mid-run and
demand a full re-login.

---

## Environment / trigger conditions

- 10+ parallel Codex sessions against ChatGPT accounts; broker seeded with
  per-account stores under `~/.local/share/oauth-mux/codex/<acct>/auth.json`
  (`src/main.zig:16591-16608` — `codexStoreRoot` / `codexAccountDir`).
- Upstream Codex has only an **in-process** refresh guard plus a file auth
  backend with **no cross-process lock**, so independent processes race the
  refresh (matches `openai/codex#10332`).
- `oauth-mux` today uses **per-session in-process proxies with no shared daemon**
  (`README.md:257`). N concurrent `oauth-mux codex` invocations = N independent
  OS processes, each with its own materializer pointed at the **same** per-account
  `auth.json`, with **no `flock`/`O_EXCL`/mutex** around the read → refresh →
  write path.

A second, lab-specific trigger (out of `oauth-mux` scope) compounded the
2026-05-31 incident: a home-manager `sops-nix` mechanism materialized a **stale**
snapshot of `~/.codex/auth.json` over the live rotating token on every switch
(disabled at the lab layer). That is **not** the `oauth-mux`-owned defect; the
refresh race below reproduces independently of it.

---

## Root cause (oauth-mux-owned, cited to file:line)

OAuth refresh tokens here are **single-use / rotating**: a successful refresh
invalidates the refresh token it was issued against and returns a new one. Any
second use of the old token is rejected.

### The unguarded critical section

`refreshCodexAccountAuthFile` — `src/broker_loader.zig:362-390`:

1. `readFileAlloc(path)` (`:372`) — read the current `refresh_token`.
2. `parseCodexAuthRefreshMaterial` (`:375-377`) — extract `refresh_token`.
3. `oauth.refreshToken(allocator, token_url, refresh_token, client_id)` (`:381`)
   — network POST to `def.auth.token_endpoint` (`:380`;
   codex = `https://auth.openai.com/oauth/token`, `src/provider_schema.zig:721`)
   that **rotates / invalidates** the supplied refresh token server-side
   (`src/oauth.zig:18`).
4. `buildRefreshedCodexAuthJson` → `writeFileReplace(path, …)` (`:385-387`).

**No lock is held across `:372 → :387`.** Two processes whose access tokens both
crossed the `exp - 300s` boundary (`refreshCodexAuthState`, `:398-404`) each read
the **same** `refresh_token` at `:372` and each POST it at `:381`. The server
accepts the first (rotates) and returns 401 to the rest.

Reached per outbound request via the proxy: `materialize_chatgpt`
(`src/adapters/codex/wire_proxy.zig:562`) → `materializeChatgpt`
(`src/broker_loader.zig:641-695`, read `:683` / refresh `:687` / re-read `:688`)
→ `refreshCodexAuthBeforeMaterialize` (`:406-424`) → `refreshCodexAccountAuthFile`.
The same `refreshCodexAccountAuthFile` is also called by the preflight sweep
`repairRefreshableCodexAuthFailures` (`:107`, call site `:138`).

### `writeFileReplace` is atomicity, NOT mutual exclusion

`src/broker_loader.zig:552-580`: writes to a **random** `path.tmp-<rand>` with
`.exclusive = true` (O_EXCL on the unique tmp name only — never contended),
`fsync`, then `rename` over `path`. This guarantees readers never see a torn
file, but it is **last-writer-wins** and does **not** serialize the network POST
at `oauth.zig:18`. The contended resource is the POST, which `writeFileReplace`
does not gate.

### Second double-spend channel: child-preserved auth

`shouldPreserveChildAuth` (`src/adapters/codex/wire_proxy.zig:1645-1654`) returns
true when inbound `ChatGPT-Account-ID` matches the elected account and
`Authorization` is non-empty; `setOutboundAuthHeaders` (`:1616-1643`) then
**forwards the child's own bearer** (`:1627-1628`) instead of substituting the
broker's elected token (`:1637-1638`). The Codex child has its own in-process
refresh and **its own unlocked file backend**, so it can rotate the shared token
out-of-band while another `oauth-mux` process is mid-refresh on the same account
(`proxy_preserved_child_auth` / `same_account_child_refresh`, `:584-589`). So even
brokered multi-session can double-spend.

### The fix primitive already exists in-tree — it just isn't applied here

`oauth-mux` already ships a per-account exclusive file lock keyed exactly right,
but wired only to the **interactive repair** flow, not the silent refresh path:

- `repair_state.acquireRepairLock` — `src/repair_state.zig:362-397`
  (`createFileAbsolute` with `.lock = .exclusive`, keyed `<provider>-<account>.lock`;
  path helpers `:438-454`); probe `probeRepairLock` `:399-418`. Callers:
  `src/main.zig:2897`, `:5168`, `src/runtime.zig:156`.
- In-process-only `std.Thread.Mutex` (`src/main.zig:14421`, `:14617`) — **useless
  across the N session processes.**

A repository search confirms **zero** `flock` / `O_EXCL` / `LOCK_EX` / `fcntl` /
cross-process `Mutex` in the refresh + write path of `src/oauth.zig` or
`src/broker_loader.zig`. The per-account mutex the specs promise
(`docs/spec/broker-mcp-contract-2026-05-03.md:283`,
`docs/spec/codex-adapter-contract-2026-05-03.md:501`, both citing
`openai/codex#9634`) exists only as prose. That is the defect.

---

## Repro (provable, test-verifiable, no spend) — proposed acceptance gate

> ⚠️ The reproduction below is the **proposed acceptance gate to be implemented
> alongside the fix**. It does not exist in the tree yet. It is specified
> precisely so the failing-then-passing proof lands in the same PR(s) as the fix.

### What must be stubbed (and what must NOT)

The refresh POST that rotates the token targets the **OAuth token endpoint**
(`def.auth.token_endpoint` → `https://auth.openai.com/oauth/token`,
`src/provider_schema.zig:721`), **not** the `chatgpt.com/backend-api/codex/responses`
proxy upstream that `scripts/test-stub-upstream.py` simulates. A no-spend repro
must therefore override the provider definition's **`token_endpoint`** to a local
stub — exactly the seam the existing test
`"materializeChatgpt refuses stale codex token when refresh fails"` already uses
(`src/broker_loader.zig:936-990`, which sets `"token_endpoint": "://invalid"` at
`:959`). Extending `test-stub-upstream.py` would **not** intercept the refresh and
would not exercise the race.

Also note: `oauth.refreshToken` returns only `error.RefreshDenied` on a non-200
and **discards the response body** (`src/oauth.zig:55-57`). The literal upstream
strings (`token_revoked`, "refresh token already used…") never flow through
oauth-mux's own output from this path, so the discoverable strings must be
**emitted by the test/stub print lines and the stub's 401 body** — they are the
search-indexed proof, not incidental log output.

### Unit test (primary proof) — new block beside the refresh unit tests (`src/broker_loader.zig:865-1014`)

An in-process stub OAuth **token endpoint** (no network, no spend) holding
`consumed: ?[]const u8`. On `grant_type=refresh_token`:
- token == current & not consumed → mark consumed, rotate, return **200** with the
  rotated token;
- token already consumed → return **HTTP 401** body
  `{"error":"token_revoked","error_description":"Your access token could not be refreshed because your refresh token was already used. Please log out and sign in again."}`.

Seed one `auth.json` with an **expired** access JWT (`exp <= now + 300`, so
`refreshCodexAuthState == .needed`, `:398-404`) and a known `refresh_token`. Point
the codex provider def `token_endpoint` at the stub. Spawn **N=8** threads each
calling `refreshCodexAccountAuthFile`.

> Caveat to validate during implementation: an N-thread test exercises the
> cross-process lock only if the fix uses an OS file lock (Zig `.lock = .exclusive`
> → `flock`), which contends across independent open-file-descriptions within one
> process too. Confirm this holds on the target platform rather than assuming it.

Distinctive output markers (hardcoded in the test, for discoverability):

```
# reproduces TODAY (lock absent): assert revoked_count >= 1 && stub.post_count > 1
REFRESH-RACE-REPRO: detected token_revoked
REFRESH-RACE-REPRO: upstream said "refresh token already used. Please log out and sign in again."
REFRESH-RACE-REPRO: server refresh_token POST count = 8 (expected 1 under serialization)

# passes WITH serialization (lock present): assert stub.post_count == 1 && revoked_count == 0
REFRESH-RACE-FIXED: 8 concurrent refreshers, 1 token-endpoint POST, 0 token_revoked
REFRESH-RACE-FIXED: serialized via per-account flock (provider:account)
REFRESH-RACE-FIXED: all 8 sessions converged on one rotated refresh_token
```

Test name carries the searchable strings, e.g.
`test "refresh race: concurrent refreshers do not double-spend single-use token (token_revoked / refresh token already used)"`.
Run via `zig build test` (`build.zig:31-38`; `just test`).

### No-spend cross-process smoke — proposed `scripts/smoke-codex-refresh-race.sh` / `just smoke-codex-refresh-race`

Closest existing assets to reuse:
- `scripts/smoke-codex-cassette-replay.sh:246-248` already drives
  `POST /oauth/token → 401` with body code `redacted_refresh_reused` — the nearest
  working pattern for stubbing the **token endpoint** with a refresh-reuse 401.
- `scripts/smoke-codex-concurrent-sessions.sh` is the concurrency harness, but it
  deliberately uses **distinct** accounts (which is exactly why it does not catch
  this) — the new smoke must point **both** session entries at **one shared**
  account store.
- `scripts/test-stub-upstream.py` already supports forcing 401 via
  `OMUX_STUB_ALWAYS_STATUS` (`:98`) and `OMUX_STUB_ACCOUNT_STATUS_JSON` (`:100`),
  but (a) it is the `/responses` upstream, not the token endpoint, and (b) it has
  no `token_revoked` body / revoke-after-first-refresh mode. The smoke needs a
  **token-endpoint** stub with a stateful "revoke after first refresh" mode.

- **Failing variant** (lock off): token-endpoint stub log shows **≥2** refresh
  POSTs of the same token; ≥1 session emits a `token_revoked` frame. Terminal:
  `refresh-race smoke: REPRODUCED token_revoked double-spend (N refresh POSTs > 1).`
- **Passing variant** (lock on): exactly **1** refresh POST; both sessions succeed;
  `jq -r '.tokens.refresh_token' <store>/auth.json` shows one rotated token; zero
  `token_revoked` frames. Terminal: `all <k> assertions passed.`

---

## Proposed fix (summary; full design in the contract doc)

Full design + acceptance plan:
`docs/spec/codex-refresh-serialization-contract-2026-05-31.md`.

1. **Cross-process refresh serialization (the OAuth semaphore).** Add a blocking
   per-`provider:account` exclusive file lock around the read → refresh → write
   critical section in `refreshCodexAccountAuthFile` (`broker_loader.zig:362-390`),
   with a **double-checked re-read** under the lock (re-run `refreshCodexAuthState`;
   if a peer already rotated, skip the POST). Reuse the existing
   `repair_state.acquireRepairLock` idiom (`repair_state.zig:362-454`) so refresh
   and interactive repair contend on the same domain. Kernel `flock` auto-releases
   on process death (no stale-lock GC). Collapses N refreshes into 1 POST + (N-1)
   no-ops.
2. **Close the child channel.** For accounts oauth-mux owns (`config_dir != null`,
   `broker_loader.zig:122,415`), make `shouldPreserveChildAuth`
   (`wire_proxy.zig:1645-1654`) return `false` so the broker is the sole refresher.
3. **Adapter-agnostic serial re-login.** When refresh is impossible (already
   revoked), a serialized, user-mediated re-enrollment surface (CLI + optional
   loopback callback + minimal `127.0.0.1` web UI) re-auths each `provider:account`
   exactly once across sessions, on the same lock. See the contract doc.

Rejected: a mandatory shared broker daemon (contradicts the per-session/no-daemon
model, `README.md:257`) and a hand-rolled sentinel file (SIGKILL-orphan / TTL
liabilities the kernel `flock` avoids).

---

## References

- Upstream class: `openai/codex#10332` (incident error signature);
  `openai/codex#9634` (cited by the in-repo specs).
- Per-session / no-daemon model: `README.md:257`.
- Unguarded refresh critical section: `src/broker_loader.zig:362-390` (POST `:381`,
  token URL `:380` → `src/provider_schema.zig:721`); `src/oauth.zig:18`,
  `:55-57` (body discarded, returns `error.RefreshDenied`).
- Atomic-but-not-locked write: `src/broker_loader.zig:552-580`.
- Materialize path: `src/adapters/codex/wire_proxy.zig:562`;
  `src/broker_loader.zig:641-695`, `:406-424`, `:398-404`; preflight sweep
  `repairRefreshableCodexAuthFailures` `:107`/`:138`.
- Child double-spend channel: `src/adapters/codex/wire_proxy.zig:1645-1654`,
  `:1616-1643`, `:584-589`.
- Existing lock idiom to reuse: `src/repair_state.zig:362-397`, `:438-454`;
  readiness `src/runtime.zig:156-158`.
- Account store path (matches incident): `src/main.zig:16591-16608`.
- Test/smoke scaffolding: `build.zig:31-38`; refresh unit tests
  `src/broker_loader.zig:865-1014` (token-endpoint override seam at `:936-990`,
  `:959`); `scripts/smoke-codex-concurrent-sessions.sh`;
  `scripts/smoke-codex-cassette-replay.sh:246-248`; `scripts/test-stub-upstream.py:98-160`.
