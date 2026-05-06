# Harness Adapter Pattern
Date: 2026-05-03
Status: design pattern doc for non-Codex adapters. Anchor:
`docs/spec/broker-mcp-contract-2026-05-03.md`. Codex-specific worked
example: `docs/spec/codex-adapter-contract-2026-05-03.md`.
Store-boundary companion:
`docs/spec/harness-session-authority-bridge-2026-05-05.md`.

## What an adapter is, in one sentence

An adapter is a small process that owns one user-facing AI harness's
session lifecycle, materializes broker-elected credentials into the
shape that harness expects, observes that harness's quota/auth signals,
and asks the broker to swap accounts when the active one is exhausted —
without restarting the harness child.

Concretely: `oauth-mux <harness>` runs an adapter. The adapter speaks
the broker MCP contract (§2 of the broker spec) on one side, and the
harness's native auth/IPC surface on the other.

## What every adapter MUST decide

Every harness has a different surface area. Before writing an adapter,
answer these twelve questions in a per-harness contract spec (the way
`codex-adapter-contract-2026-05-03.md` answers them for Codex):

1. **Token shape.** What is the credential the harness consumes? Bearer
   access token only? Access + id token + account id tuple? OAuth
   refresh token persisted to disk? API key fallback?
2. **Token storage.** Where does the harness expect to find it? File
   path with a known schema? Env var? Keyring entry? IPC handshake
   with a parent? In-memory only?
3. **Token reload semantics.** Does the harness re-read the token per
   request, cache it for the process lifetime, or have an explicit
   reload trigger (signal, IPC, file-watch)? This determines whether
   in-place swap is even reachable, and which mechanism the adapter
   must drive.
4. **Auth-failure surface.** When auth fails, what does the harness do?
   401 retry with refresh, JSON-RPC `auth/refresh` callback, exit, prompt
   user, fail silently? This determines the recovery hook.
5. **Quota-failure surface.** When quota is exhausted, what does the
   harness do? Same answer as #4 or different code path? For Codex they
   are different (401 vs 429); for other harnesses they may be the
   same.
6. **Wire interception.** Can the harness be pointed at a localhost base
   URL via env or config? If yes, the adapter can run a wire-layer
   reverse proxy and own the auth header on every request. If no, the
   adapter must rely on (3) and (4) alone.
7. **Process topology.** Does the harness have a separable "engine" the
   adapter can own (Codex's `app-server`)? Or is it a single binary the
   adapter can only sit in front of as a wrapper?
8. **TUI/UI surface.** Does the harness render its own TUI we can stay
   out of, or does the adapter need to render? If the adapter must
   render, what is the minimum-viable surface?
9. **Workspace / account-boundary policy.** Does the harness/server
   refuse a cross-account swap (work vs personal)? What's the boundary?
10. **Refresh-token rotation.** Does the provider rotate refresh tokens
    on every refresh (OAuth 2.1 §4.3.1)? Does it tolerate concurrent
    refreshes from different processes? (Most don't.)
11. **ToS posture.** What does the provider's terms say about running
    multiple subscription accounts in rotation? The adapter must honestly
    label this; we implement what is technically possible, we name what
    is policy-controversial, we do not advocate.
12. **Session authority.** Which local files or service APIs implement
    resume/history/session continuity? Can the adapter retain that
    authority while keeping auth/config mux-owned? If the harness exposes
    only one home directory, follow
    `docs/spec/harness-session-authority-bridge-2026-05-05.md` before
    claiming managed-session parity.

If any of these cannot be answered from public source / docs /
captured wire evidence, that gap is a Phase 0 capture task before the
adapter is written. Adapters MUST NOT be written against assumed shapes.

## What every adapter MUST do (the contract restated for clarity)

Per broker spec §3.1, every adapter MUST:

1. Speak MCP `surface_version: 1` against the broker.
2. Call `surface/handshake` before any other broker method.
3. Call `account/select` (or `account/swap`) before presenting credentials
   to its harness for any request the broker is supposed to govern.
4. Materialize tokens via `credential/materialize` (or local equivalent
   the adapter can prove is broker-authorized).
5. Report every observed quota/rate-limit/auth event from its wire path
   via `quota/observe` *before* attempting recovery.
6. On its harness exhibiting account-blocked behavior, attempt
   `account/swap` exactly once per turn boundary; on the second attempt
   failing, surface a typed handoff and stop.
7. Report a clean, machine-readable claim level bounded by what was
   actually achieved this session.
8. Redact tokens, refresh tokens, id tokens, account ids (where
   reasonable), and credential file paths from anything emitted to the
   broker, the user's terminal, and the event log.

## What every adapter MUST NOT do

Per broker spec §3.3:

1. **Restart its harness child to recover.** Restart is not a broker
   outcome at any level. The adapter MUST report `seamless: false` and
   surface honestly rather than respawning.
2. Materialize tokens behind the broker's back (read provider auth
   stores directly without going through `account/select` first).
3. Print token material to stdout/stderr/JSON.
4. Claim a higher claim level than the broker's `claim_floor` for the
   session.
5. Modify upstream-CLI-owned credential stores without an explicit
   `credential/refresh` admission for the affected account.

## Three reference architectures

Different harnesses fall into different topologies. Each has a different
adapter shape.

### Architecture A — IDE-protocol broker (Codex-style)

The harness exposes a JSON-RPC IDE-integration surface (Codex's
`app-server`). The adapter spawns the harness's IDE engine as a child,
becomes the IDE-role client, and answers auth-refresh callbacks with
broker-elected credentials.

Adapter components:
- IDE-protocol JSON-RPC client.
- (Optional but usually required) wire-layer reverse proxy under the
  engine, for quota signals the IDE protocol cannot itself recover from.
- Minimal terminal renderer or stdio passthrough for the user.

Worked example: `docs/spec/codex-adapter-contract-2026-05-03.md`.

### Architecture B — Wire-layer-only proxy (API-key-style)

The harness has no IDE-protocol surface, but consumes credentials via
HTTP and tolerates a base-URL override. The adapter runs a localhost
reverse proxy, points the harness at it, signs every outbound request
with the elected account, and intercepts quota signals at the wire.

Adapter components:
- Wire-layer reverse proxy.
- Optional config bootstrapper to set the base URL.
- No process management beyond `execvp`'ing the harness with the right
  env.

This is the cheapest architecture when the harness's auth is purely
"present a bearer token per request" and there's a base-URL override.
Examples to evaluate this for: aider with custom OpenAI base URL,
tools using `OPENAI_BASE_URL`, future Cursor agent if it exposes an
override.

### Architecture C — Process-wrapper passthrough (last resort)

The harness exposes neither an IDE-protocol surface nor a base-URL
override. The adapter cannot intercept the wire and cannot drive auth
refresh through a hook. The honest result: the adapter can only stage
the right credentials at process start, and can only observe failure at
process exit. This is Level 1–2 only; Level 3 is unreachable.

If a harness lands here, the adapter exists as documentation of
limitation, not as a product surface. The user-facing message is honest:
"`oauth-mux <harness>` runs the harness with the elected account, but
this harness does not expose a hook for in-place swap. On exhaustion, you
will need to restart the harness manually." We do not silently restart on
their behalf.

Better outcome for harnesses in this category: contribute upstream until
the harness exposes Architecture A or B.

## Naming and CLI shape

Adapter binaries are subcommands of `oauth-mux`:

```
oauth-mux codex      # Architecture A
oauth-mux claude     # Architecture A or B (TBD by capture)
oauth-mux cursor     # Architecture B (likely)
oauth-mux pi         # TBD
```

Each adapter accepts the same standard flags:

- `--profile <name>` — broker profile to draw accounts from.
- `--account <provider:account>` — pin one account, no swap.
- `--no-broker` — bypass adapter, run bare harness with no mux.
- `--json-status` — NDJSON status frames to stderr.

After `--`, all remaining args are forwarded to the underlying harness
unchanged.

## Status frame schema (shared)

Every adapter emits the same shaped NDJSON frames under `--json-status`.
This lets external monitoring/CI/wrappers consume any adapter without
per-adapter parsing logic.

```jsonc
{ "kind": "session_started", "adapter": "codex", "session_id": "...", "selected_account": "codex:max-1", "claim_level": "broker_owned" }
{ "kind": "account_swap", "from": "...", "to": "...", "reason": "quota_exhausted", "via": "<adapter-specific mechanism>", "claim_level": "next_turn_seamless" }
{ "kind": "credential_refresh", "account": "...", "trigger": "proactive_exp" | "unauthorized_401", "outcome": "ok" | "failed" }
{ "kind": "quota_observed", "account": "...", "kind_detail": "rate_limited" | "tier_insufficient" | "provider_5xx", "retry_after_s": 12 }
{ "kind": "session_ended", "session_id": "...", "turns": int, "swaps": int, "final_claim_level": "..." }
```

The `via` field on `account_swap` is the only adapter-specific freeform
field; everything else has a fixed enum of allowed values per the broker
spec.

## When to write a new adapter

Start a new adapter when, and only when:

1. The harness has paid users hitting quota walls regularly enough that
   in-place mux meaningfully changes their workflow. (If quotas hit
   monthly, not weekly, a wrapper tells them to manually switch is
   probably enough.)
2. The twelve questions above are answerable from public source +
   captured wire evidence.
3. The harness's architecture maps to A, B, or C, and you are honest
   about which.
4. There is at least one cohort of multi-account paid users willing to
   dogfood the adapter.

Do NOT start a new adapter to "round out the matrix" or "match
competitor X." Each adapter is a maintenance burden against an
unstable upstream protocol.

## Maintenance and protocol drift

When an upstream harness changes its auth or IPC protocol:

1. The adapter's tests against captured fixtures fail first; this is by
   design.
2. The adapter is updated against new captures.
3. The broker MCP surface is NOT changed unless the new harness shape
   reveals a contract bug. Adapter-specific concerns stay in the
   adapter.

If an adapter would require a broker change to handle a new harness
shape, that is a signal the broker contract was over-fit to the prior
harness; resolve in the broker spec, not in the adapter.

## Closing rule

The broker is one. The adapters are many. Each adapter is the thinnest
thing that turns its harness into a Level 3 (`next_turn_seamless`)
citizen of the broker's account pool. If an adapter is more than the
thinnest such thing, it is doing too much; if it is less, it is not
yet honest.
