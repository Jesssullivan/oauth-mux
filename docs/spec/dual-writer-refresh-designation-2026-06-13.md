# Dual-Writer Refresh: serializing the mux warm loop against native-CLI rotation (designation)

Status: DESIGNATED (2026-06-13, revised after adversarial review). The chosen
mechanism for TIN-2059 — the last gate before any builtin `proactive_refresh`
grant flips (TIN-2058). Builds on the refresh substrate landed this turn:
TIN-2070 (keychain write), TIN-2058 (authority split), TIN-2073 (refresh-path
flock + under-lock revalidation), TIN-2074 (field-preserving writeback).
Companion to the reauth orchestrator designation and the auth-state-model
taxonomy.

> Adversarial review (2026-06-13) rejected the first draft's "R4 SOLVED" and
> "freshness window shrinks to near-zero" claims as false against the code.
> This revision corrects them: several races are NOT covered by today's code
> and become **hard prerequisites** for the grant flip, enumerated in the
> Prerequisites section. The grant flip is gated on that checklist, not on
> this doc.

## The hazard

OAuth refresh tokens are single-use: a successful refresh rotates the RT and
invalidates the one presented. Two refreshes of the same chain that both read
the RT before either rotates each spend a now-different RT — the provider keeps
the last write and the other party's freshly-minted access token is orphaned,
and a careless writer may persist a superseded RT over a fresh one. This class
burned the project twice (sops-nix stale-`auth.json` re-materialization revoked
the rotated RT system-wide; temp-home muxxing poisoned the canonical store).

The warm loop proactively refreshes credentials the **native claude/codex CLIs
also own and rotate**. oauth-mux's locks cover only oauth-mux's own
entrypoints; a native CLI takes no oauth-mux lock.

## The one invariant that must always hold

**The credential store always contains exactly one internally-consistent
`(access_token, refresh_token[, expiry])` tuple, and oauth-mux never persists a
refresh token it did not itself just mint.** This is guaranteed by
field-preserving-writeback-on-success (TIN-2074): `attemptRefresh` writes only
after `oauth.refreshToken` succeeds, and writes the `(at, rt)` pair *it* just
received — never a snapshot RT, never a partial. A failed refresh writes
nothing. This invariant holds regardless of how many parties race, and it is
the floor the whole design stands on: the worst a race can cost is a *wasted*
refresh (one party's rotation is discarded), never a corrupt or
internally-inconsistent store. The serialization mechanisms below exist to
*also* prevent the wasted-refresh / mid-session-revocation outcomes, not to
prevent corruption (the invariant already does that).

## Threat model — four writer pairs

| # | Writer A | Writer B | covered by code today? |
| --- | --- | --- | --- |
| R1 | warm-loop refresh | another mux refresh (exec/env/probe tick) | YES — shared per-account flock + under-lock revalidation (TIN-2073) |
| R2 | warm-loop refresh | a managed native session (`oauth-mux codex`) | codex YES (shared flock); **claude NO** (no managed adapter) |
| R3 | warm-loop refresh | a **bare** native CLI (run directly) | NO by design — accept + invariant + mitigate |
| R4 | warm-loop refresh of account X | a live session of a DIFFERENT config account sharing X's identity | **NO — the warm loop is not in the identity-lock domain** |

## Per-race analysis

### R1 — mux vs mux: covered (TIN-2073)

`attemptRefresh` takes the per-`(provider,account)` repair flock (nonblocking),
revalidates under the lock, and on a peer rotation already persisted, adopts it
(`concurrent_rotation_detected`) without an endpoint call. Held lock → typed
`refresh_lock_held` deferral. Exactly one rotation per contended window —
**when expiry is parseable** (see the codex-expiry prerequisite; the
adopt-skip is gated on a non-null future `expires_at`).

### R2 — mux vs managed session: codex covered, claude NOT

The codex adapter holds `acquireRepairLockBlocking("codex", account)` across
spawn→wait→finalize; the warm loop's `attemptRefresh` takes the *same*
`("codex", account)` key nonblocking and defers while the session is live. At
session end `observeAuthWriteback` imports the rotated `auth.json` under a
source-hash CAS that refuses on independent source change. **This is entirely
codex-specific and file-based.** Claude has no managed adapter, so every Claude
session is "bare" (R3) — R2-for-claude is **uncovered**. See the Claude gate.

### R4 — warm refresh vs a live session of a sibling config account, same identity: NOT COVERED (was wrongly marked solved)

The identity flock (`codex-identity-<sha256_12(account_id)>`) is taken only by
the **managed session path** (adapter), never by `attemptRefresh`. The warm
loop takes only `("codex", config_account)`. So two enrolled config accounts
backed by one upstream identity — **the live `max-1 ≡ max-4` Apple-ID
duplicate** (codex-account-inventory) — are in different lock files:
`codex-max-1.lock` vs `codex-max-4.lock`. A warm refresh of `max-4` does NOT
block on a live `max-1` session, and the two rotate the shared single-use chain
concurrently. The store-invariant prevents corruption, but the live session's
*next* native rotation then fails on a consumed RT — an in-session
self-revocation, exactly the hazard the identity lock was built (as a blocking
refusal) to prevent. **This is why R4 cannot borrow R3's "benign residual"
argument: one party is long-lived.** Fix is a hard prerequisite (below):
the warm loop must acquire the identity lock, and/or config-level identity
dedup must forbid two accounts sharing one `account_id`.

### R3 — mux vs bare native CLI: accept + invariant + mitigate (no lock possible)

A CLI invoked outside oauth-mux takes no observable lock. The design does not
serialize it; it relies on the store-invariant plus mitigation:

1. **Store-invariant is the safety floor** (above): even if a bare CLI and the
   warm loop both succeed (e.g. under a provider RT-reuse **grace window** —
   see below), the store ends with one consistent pair; the loser's rotation is
   wasted, not corrupting. Neither party persists a stale RT, because each
   writes only the RT it just minted.
2. **Freshness re-read narrows the wasted-refresh window** — *when expiry is
   parseable*. `attemptRefresh`'s under-lock re-read adopts an
   already-refreshed credential and skips the endpoint. This works for claude
   (ms `expiresAt`, TIN-2074) but is **dead for codex today**: codex's
   `auth.json` carries no `expires_in`/`expires_at`, only `last_refresh` + JWTs,
   so `expires_at` is null, the adopt-skip never fires, and `validateToken`
   never even enters the refresh path via expiry. Codex needs JWT-`exp`
   derivation first (prerequisite).
3. **Provider RT-serialization is a *secondary* effect, not the safety basis.**
   Whether Anthropic/OpenAI invalidate the old RT atomically or allow a brief
   reuse grace is unproven and MUST NOT be assumed. The design is correct
   either way because of the store-invariant; if rotation is strictly atomic we
   additionally get "only one POST succeeds," which is a bonus, not a
   load-bearing premise.
4. **Operator contract**: running a bare native CLI for a warmed account is the
   operator's explicit choice; documented as "supported, with a possible
   one-cycle wasted refresh / re-login if you refresh by hand inside the warm
   window." No bare-CLI shim interception (rejected: brittle, unnecessary given
   the invariant).

## Claude gate (elevated from a sub-bullet — this is a grant-flip blocker)

Claude's store is the login keychain item (TIN-2060); the Claude CLI writes it
on its own refresh with no oauth-mux lock, and there is **no managed Claude
adapter** today. Therefore for Claude: R2 is uncovered (collapses into R3 for
the *entire* lifetime of every interactive Claude session, not a narrow
window), and the store-invariant is the *only* protection. The keychain item's
structural per-account isolation (distinct suffixed service, TIN-2060) means a
warm refresh of account X cannot touch account Y, and `security
add-generic-password -U` replaces the item atomically — but atomicity does
**not** prevent a read-by-us → CLI-writes → write-by-us interleave from wasting
a rotation (it only prevents a torn write). A Claude grant flip therefore rests
**entirely** on the R3 store-invariant argument plus accepting whole-session
bare-CLI residual. That is acceptable ONLY if disclosed and operator-consented;
it is a distinct, higher-residual posture than codex and must not be flipped on
silently. A managed Claude adapter that takes the per-account flock (the #354
lane) is what would give Claude true R2 coverage.

## Hard prerequisites before ANY builtin `proactive_refresh` grant flips

This checklist — not this doc — gates the flip:

1. **Identity-lock participation in the warm loop (R4)** — `attemptRefresh`
   computes the upstream identity hash and acquires
   `("<provider>-identity", hash)` (nonblocking, defer-on-held) in addition to
   the per-account lock, in the established lock order (account then identity).
   Tracked as **TIN-2043**, now a hard blocker. *And/or* config-load identity
   de-dup that refuses two enrolled accounts sharing one `account_id` (closes
   the `max-1 ≡ max-4` shape at the source).
2. **Codex JWT-expiry derivation** — parse the access-token JWT `exp` (or a
   computed `last_refresh + ttl`) into `expires_at` so codex can (a) enter the
   proactive-refresh path at all and (b) take the freshness adopt-skip.
   Without it the warm loop is a no-op for codex and R1/R3 narrowing is dead.
3. **Warm-loop scheduler at ~75% lifetime (#355 lane)** — there is no scheduler
   in the tree today; the timing mitigation is unbuilt. Required for the window
   to be small in practice.
4. **Claude posture decision** — either a managed Claude adapter for true R2
   coverage, or an explicit operator-consented "bare-residual accepted" flag
   gating the claude grant specifically.
5. **Live + synthetic proof** — a cassette test racing a warm refresh against a
   simulated peer on one account (exactly one RT spent; skip/defer exercised;
   store never carries a superseded RT), AND the live two-account concurrent
   leg (TIN-1852) extended with a warm-loop tick fired *during* a live session,
   asserting the tick defers and spends zero extra RTs. Unit-green ≠ working.

## Acceptance mapping (TIN-2059)

- "Provably never spends two RTs of one chain" — holds for R1 and R2-codex by
  the shared flock + under-lock revalidation (given prereq 2 for codex). Holds
  for R4 only once prereq 1 lands. For R3 (and claude-as-R3) the weaker but
  sufficient guarantee is the store-invariant: never a corrupt store, at most a
  wasted refresh; "two RTs spent" is possible under a provider grace window but
  is non-destructive.
- "Cassette/synthetic test" and "live leg with a warm tick" — prereq 5.

The design's deliverable (this doc + the corrected mechanism) is complete; the
**grant flip remains blocked** until prerequisites 1–5 land with the live leg
recorded.
