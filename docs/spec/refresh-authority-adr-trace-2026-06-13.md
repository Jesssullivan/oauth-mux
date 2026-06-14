# ADR Trace: Refresh-Authority / Keepalive Work (2026-06-12 → 2026-06-13)

Status: ADR trace (synthesis of decisions, not a new decision). Compiled
2026-06-13 from the decision docs in `docs/spec/`, the merged git history
(PRs #389–#400), and the project memory. Maps every architectural decision in
the refresh-authority push that gates the builtin `proactive_refresh` grant
flip → the keepalive warm loop → the TIN-2057 golden metric.

## The spine (one line)

TIN-2060 (keychain truth) → TIN-2070 (keychain write) + TIN-2058 (authority
split) → TIN-2073 (serialization) + TIN-2074 (field-preserving writeback) +
TIN-2087 (codex expiry) + TIN-2043 (identity lock) + TIN-2039 (probe lock) →
**TIN-2059 (dual-writer design)** → builtin grant flip → #355 scheduler + live
proof → TIN-2057 (golden metric).

Frontier (2026-06-13): the entire substrate + TIN-2059's *design* are landed.
The grant flip is gated on the remaining prerequisites — #355 warm scheduler,
the live concurrent-proof leg, and the Claude posture decision.

## Decision timeline

| # | Decision | Ticket | PR / commit | Rationale | Corrected / superseded |
|---|----------|--------|-------------|-----------|------------------------|
| 1 | Mediator-on-top-of-engine reauth orchestrator | TIN-2064 | #389 d56c4af | Keep the deciding layer pure; engine executes; consent is the seam | Adversarial review corrected the "unchanged order" claim, exposed approval-doesn't-reach-engine; added the flow-composition car |
| 2 | Claude keychain ground truth (`Claude Code-credentials-<sha256(dir)[:8]>`, per-config-dir, no `.credentials.json`) | TIN-2060 | #390 afee957 | The whole Claude lane is gated on where creds live + whether 2 accounts clobber (they don't) | Established `credential_filename`/`credential_template` as dead-on-macOS; surfaced the session-bleed defect |
| 3 | macOS keychain write + suffixed read | TIN-2070 | #391 76b0966 | Claude refresh writeback is impossible without keychain write | Built on TIN-2060; migrated live xoxd+sulliwood file→keychain |
| 4 | Refresh-authority split (provider grant × operator consent) | TIN-2058 | #392 70e5ed3 | Refreshing a credential the native CLI also owns must be deliberate, not default | Its review found 2 majors → TIN-2073 + TIN-2074; builtins declare NO grant until both land |
| 5 | Auth-state-model taxonomy (home-scoped-file vs os-keystore-singleton; a (provider,platform) fact) | TIN-2078 (doc) | #393 7da7a2f | An extensibility story expressing only codex overclaims; Claude's 3 singleton layers need naming | Scoped "start as data, not Zig" to home-scoped-file; TIN-2078 (schema impl) remains Backlog |
| 6 | Serialize + budget-gate pipeline refresh | TIN-2073 | #394 4e08505 | Unserialized refresh = the RT self-revocation class that burned the project twice | Fixed TIN-2058 review major #1; review caught a live TOCTOU + probe-budget bypass |
| 7 | Field-preserving writeback + expiry units (claude=ms) | TIN-2074 | #395 62cdbbf | Lossy template drops claude `expiresAt` (→ never-refresh) + codex `id_token` (identity) | Fixed major #2; round-2 review caught a self-introduced wrapper-guard regression |
| 8 | Dual-writer refresh designation (store-invariant + R1–R4 threat model) | TIN-2059 | #396 bb90a4c | Last/hardest design gate; states which races are covered vs accepted residuals | **KEY CORRECTION**: first draft falsely claimed "R4 SOLVED" + "freshness→near-zero"; review rejected both → became hard prerequisites (TIN-2043, TIN-2087) |
| 9 | Codex JWT-exp expiry derivation | TIN-2087 | #397 e07cbf6 | Codex `auth.json` has no expiry field; without it the warm loop is a codex no-op | Dual-writer prereq #2; review caught a ReleaseSafe `@intFromFloat` panic vector |
| 10 | Warm/background refresh takes the per-identity flock | TIN-2043 | #398 58251b3 | Two config accounts on one identity (max-1≡max-4) could double-spend → in-session self-revocation | Dual-writer prereq #1 — **closed the R4 race the corrected #396 review proved was unsolved** |
| 11 | Probe path takes the account lock (lock_busy) | TIN-2039 | #399 a2a25bf | `codex exec` in a probe rewrites auth.json racing a live session; last mux-vs-mux residual | + #400 testRuntimeDir backstop (lock tests stopped polluting the real runtime dir) |

## The dependency graph

```
                       TIN-2060 (#390) keychain truth
                                 │
            ┌────────────────────┴───────────────────┐
            ▼                                         ▼
      TIN-2070 (#391)                           TIN-2058 (#392)
      keychain WRITE                            authority SPLIT
            │                  ┌───────────────────┴──── review: 2 majors
            │                  ▼                         ▼
            │            TIN-2073 (#394)           TIN-2074 (#395)
            │            serialize refresh         field-preserving writeback
            │                  │     ┌─────────────────┤
            │                  │     ▼                 ▼
            │                  │  TIN-2087 (#397)   TIN-2043 (#398)
            │                  │  codex JWT-exp     per-IDENTITY flock (R4)
            │                  │     │   TIN-2039 (#399) probe lock │
            └──────────────────┴─────┴──────────┬───────────────────┘
                                                ▼
                                       TIN-2059 (#396)  DUAL-WRITER design
                                       store-invariant + R1/R2/R3/R4
                                                │
                                                ▼
                          ┌──────────────────────────────────────────┐
                          │  builtin proactive_refresh GRANT FLIP     │ ◀── BLOCKED
                          │  gated on the checklist, not the doc      │
                          └──────────────────────────────────────────┘
                                                │
                                                ▼
                          #355 warm SCHEDULER (TIN-1825) + LIVE proof
                          + Claude posture (TIN-2054 guard, #354 adapter)
                                                │
                                                ▼
                                       TIN-2057 golden metric

  RELATED BRANCHES: TIN-2064 (orchestrator) · TIN-2078 (declarable os-keystore)
  · TIN-2077 (Claude concurrency gate) · TIN-2071 (incognito browser)
  · TIN-2079 (vercel/gemini units) · TIN-2053 (unpark fleet / fix vacuous CI)
```

## The two anchor auth-state models

- **home-scoped-file (codex)**: auth is a file in a relocatable `$CONFIG_DIR`;
  isolate by relocating the dir; writeback = atomic file replace + merge;
  device-code login, no browser singleton. Drove TIN-1851 home-is-store,
  TIN-1852 concurrency gate, TIN-2087.
- **os-keystore-singleton (claude/macOS)**: 3 singleton layers — keychain item
  keyed off the config-dir path (ACL-owned by the app), identity in a separate
  `.claude.json`, browser-session consent that bleeds across accounts. Drove
  TIN-2060, TIN-2070, TIN-2071, TIN-2077, and the scoped-away extensibility
  claim.

The model is a **(provider, platform) fact** — Claude is likely per-platform
hybrid (macOS keychain, Linux file, the latter unproven).

## The single load-bearing invariant

> The credential store always holds exactly one internally-consistent
> `(access_token, refresh_token[, expiry])` tuple, and oauth-mux never persists
> a refresh token it did not itself just mint.

Guaranteed by field-preserving-writeback-on-success (TIN-2074): a failed
refresh writes nothing; a successful one writes the pair *it* just minted. The
worst a race can cost is a *wasted* refresh — never a corrupt store. This
survives a provider RT-reuse **grace window**: even if a bare CLI and the warm
loop both succeed, each writes only its own minted pair, so the store ends
consistent. Provider single-use RT rotation is therefore a *bonus*, not the
basis — which is what makes R3 (mux vs bare CLI, unlockable) an acceptable
residual.

## Open architectural questions

1. **Claude posture (R2 uncovered)**: no managed Claude adapter, so every
   interactive Claude session is "bare" (R3) for its whole lifetime. A Claude
   grant flip rests entirely on the store-invariant + accepted whole-session
   residual — higher-risk than codex. Needs a managed adapter (#354 lane) or an
   explicit operator-consented flag. **And TIN-2054**: the tmpdir
   `CLAUDE_CONFIG_DIR` pattern (`pipeline.zig`) that poisoned codex for 3 weeks
   is still live for Claude with none of the Model B guards — must land before
   any Claude promotion.
2. **os-keystore CAS extension**: codex's R2 uses `observeAuthWriteback`
   source-hash CAS (file-based); there is no keychain-native equivalent.
3. **Bare-CLI residual (R3)**: permanently accepted by design; the open
   question is only per-provider disclosure/consent.
4. **Unbuilt grant-flip prerequisites**: #355 warm scheduler (TIN-1825); the
   live cassette + warm-tick-during-session proof; the structural unblock
   TIN-2053 (#344/#349/#354/#355 compile in NO CI today).
5. **Unverified TIN-2060 edges**: `CLAUDE_CONFIG_DIR == ~/.claude` suffix-or-base;
   the Linux Claude store (TIN-2070 derivation is macOS-comptime-gated).

## Provenance note

An intermediate project-memory snapshot recorded R4/identity-lock as "SOLVED"
before TIN-2043 actually landed — it predated the corrected #396 spec. Ground
truth: the merged spec + git order. R4 was genuinely closed by TIN-2043 (#398),
the final substrate commit; this trace reflects that final state.
