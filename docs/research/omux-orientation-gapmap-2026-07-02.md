> Dated orientation snapshot (2026-07-02, HEAD ba7cdd2), companion to `docs/plans/keepalive-push-2026-07-02.md`. Point-in-time research, not living truth — verify anchors and statuses at HEAD before citing. No claim here upgrades any proof_status.

# oauth-mux / omux — Gap Map: Current State vs "Never-Halt Multi-Account Keepalive, Shippable to Strangers"

Repo @ `ba7cdd2` (2026-07-02). Every claim anchored to file:line, PR, or TIN. Contradictions flagged inline with **⚠** and consolidated in §7.

---

## 1. CURRENT STATE (one page, skeptical)

**Genuinely works, live-proven:**
- **Codex N-account managed sessions**: home-is-store (`MuxMode.isolated_persistent` default, `src/adapters/codex/main.zig:108-131`), per-account `CODEX_HOME = config_dir`; two simultaneous accounts proven live with byte-stable canonical sqlite (`docs/evidence/codex-live-e2e-clean-lineage-20260612/`, `codex-concurrent-accounts-live-20260612/`; TIN-1851 Done, shipped as v0.1.13 default).
- **Refresh gate stack on the hot path** (`src/pipeline.zig:741-965`): canonical-keychain refusal (:982-1001, TIN-2054), grant×consent gate (`src/secret.zig:66-137`), per-`provider:account` flock (TIN-2073), lock-then-revalidate keyed on RT-change (:777-824), per-identity flock (:838-883, TIN-2043), field-preserving merge writeback that fails closed (:920-950, TIN-2074). Codex expiry from JWT `exp` (TIN-2087, `src/provider_schema.zig:1468`).
- **Claude credential substrate**: suffixed keychain read+write (`src/secret.zig:215-309`, TIN-2070/#391), per-config-dir service derivation verified live byte-exact (TIN-2060), `ProviderNeedsConfigDir` injection refusal (`src/pipeline.zig:1069-1094`).
- **`oauth-mux keepalive`** exists and is live-wired (`src/main.zig:366-411`); one live-proven run 2026-06-14 (`src/keepalive/warm_runner.zig:9-15`). `proactive_refresh` grant **already flipped** for claude+codex builtins (#418, `src/provider_schema.zig:787-802, 850-864`).
- **In-session codex failover**: wire-proxy 429/401 retry with fallback account before the harness sees failure (`src/adapters/codex/wire_proxy.zig:35-42, 483, 596`); live quota-handoff evidence (`docs/evidence/codex-engineered-quota-handoff-20260509/`).
- **Release v0.1.13 shipped**: tag + GH release 2026-06-12; brew/curl/deb/rpm/nix lanes verified (README.md:23-36).

**Merged but NOT evidence-proven (unit-green ≠ working):**
- Warm loop over multiple accounts: **zero committed `docs/evidence/` warm-loop runs** (TIN-2057 comment 2026-07-02). Golden metric untouched, operator-gated on real 4-account enrollment.
- Cross-process exactly-once refresh smoke: **PR #427 is still open**, not merged — ⚠ the TIN-2059 comment calls it "permanent"; at HEAD it is not landed.
- Reauth engine (`src/enroll/reauth.zig`): **zero production callers** — `ReauthOrchestrator.init` appears only in its own tests (`src/main.zig:20124-20126` is test registration only).
- device_code flow composition (#422): proven **with fakes only** (`src/enroll/flow_composition.zig:268-292`); no `std.http` anywhere in `src/enroll/`.
- `src/keepalive/ui_server.zig`: dead code, zero call sites.

**Structurally absent:**
- No resident daemon: `keepalive` defaults `iterations=1` (`src/cli.zig:318-322`); `daemon` socket is a self-declared stub (`src/daemon.zig:238-246, 477-478`).
- No Claude managed adapter at all — only `src/adapters/codex/`; bare `claude` is a dual-writer for its whole session (ADR :109-117, accepted R3).
- All reauth is vendor-CLI: `reauth run` unconditionally emits `engine_run_available:false` (`src/main.zig:5560-5584`); `flowExecutionFor()` hardcodes `.command_owned` for every provider (`src/reauth/orchestrator.zig:157-160`).
- Broker `credential/refresh` is `notImpl` (`src/broker/methods.zig:49`); the scheduler bypasses the broker via `pipeline.refreshAccount`.

---

## 2. Auth-singleton isolation per harness

### Codex (home-scoped-file model)
| | |
|---|---|
| **Primitive** | Per-account persistent `CODEX_HOME = config_dir`; `auth.json` IS the store; sessions/sqlite live there (`src/adapters/codex/main.zig:109-124, 1493-1530, 2373`) |
| **Guards** | Canonical-overlap refuse + HOME-unset refuse (:1509-1521), auth shadow backup + torn-auth restore (:2185-2227), config fresh-per-launch + scrub-on-exit (:2279-2289), per-identity session flock → `DuplicateUpstreamIdentity` abort (:1449-1468), `observeAuthWriteback` source-hash CAS for managed-session rotation (R2, :3268-3305) |
| **What breaks it** | Legacy `shared_canonical` opt-in (`TINYLAND_CODEX_MUX_MODE`, :130-143); bare `codex` CLI outside omux (R3, accepted); **in-process re-entrancy**: `repair_state.acquireRepairLockWithMode` holder registry is process-re-entrant (`entry.count += 1`) — a daemon hosting warm-tick + broker-materialize for one account can race itself (TIN-2059 wave1 finding, 2026-07-02); freshness re-read is read-then-refresh, not CAS |
| **Unproven live** | Exactly-once cross-process refresh (#427 open); engineered warm-tick-vs-live-session race (TIN-2059 implementation half) |

### Claude (os-keystore-singleton model)
| | |
|---|---|
| **Primitive** | Per-config-dir suffixed keychain item `Claude Code-credentials-<sha256(CLAUDE_CONFIG_DIR)[:8]>` (`src/provider_schema.zig:736-751`), auto-derived at config load (`src/config.zig:182-221`); identity from `<config_dir>/.claude.json` `oauthAccount.accountUuid` (`src/identity/claude_identity.zig:2-17`). Isolated by construction (TIN-2060, live-verified) |
| **Guards** | Unsuffixed-canonical-item writeback refusal (`src/pipeline.zig:982-1001`, #406); tmpdir injection refusal (`:1069-1094`, #404); merge-or-fail-closed writeback |
| **What breaks it** | **No managed adapter** — every live Claude session is a bare dual-writer (R2 uncovered for claude, ADR); **browser session-bleed** on 2nd-account OAuth — mitigation is operational only (private window), nothing in src/ (TIN-2071 open, TIN-2060-proven); **no identity flock ever engages** — claude declares no `identity_claim_path`, so pipeline step 6 is skipped AND keepalive shared-identity exclusion is vacuous for claude (`src/keepalive/warm_runner.zig:98-99`, test :295 confirms claude accounts are never excluded) → two config-dirs on the same Claude account both opted-in is an unguarded RT-family double-spend; no keychain CAS (file-hash CAS is codex-only, ADR :118-120); keychain write can wedge the held flock (no `runProcess` deadline, `src/secret.zig:273-282`); TIN-2104 suffix-derivation contradiction (open edge the exact-match guard can't cover) |
| **Unproven live** | TIN-2077 two-live-accounts clean-handoff gate — **no evidence exists**; Linux store entirely unproven (write refused off-macOS, `src/secret.zig:110-118`) |

---

## 3. Scheduling: current warm loop vs even-spread maximize-live-accounts

**What the loop does today** (`src/keepalive/warm_scheduler.zig`): per-account due at 75% of lifetime, ≥1min lead (:64-79); each tick refreshes **all** due accounts serially in one thread; `nextWakeMs` = earliest due; backoff 5s×2 cap 10min, 8 failures → `dead`; dead never blocks peers (:13-15, 185-227); shared-identity-hash exclusion (TIN-2113, `warm_runner.zig:123-148`). This is genuinely multi-account fleet warming — but it runs only as long as a foreground command lives.

**Concrete missing pieces for the goal-state scheduler:**
1. **Residency**: no daemon hosts the loop; `daemon.zig:242` says `"hosts_stay_afloat":false`; no launchd/systemd unit in-repo (TIN-1830 B.6). Keepalive is cron-shaped at best.
2. **Load spreading**: no jitter/stagger — pool build seeds every account `last_refresh_ms = now` (`warm_binding.zig:62-78`), so a fresh start aligns the whole fleet into one due-cohort; no per-provider refresh rate cap. "Spread refresh load" is currently emergent, not engineered.
3. **Durable failure state**: backoff/death live only in the in-memory pool; every invocation rebuilds fresh (`src/main.zig:382-385`) — a restarted loop forgets a dying account's history.
4. **Broker-owned refresh** (TIN-1826, blocked): `credential/refresh` notImpl (`methods.zig:49`), capability `false` (:97) — no single-writer consolidation for embedders; ⚠ the refresh-serialization project's own acceptance ("must light up the broker layer") is unmet even though the incident-fix substrate merged.
5. **Dead→reauth handoff**: a dead account just drains out of the loop; nothing routes it into the mediator, and the engine is unreachable anyway (§4).
6. **In-process gate** for a daemon running warm-tick + other writers per account (TIN-2059 re-entrancy finding) — prerequisite for hosting the loop in the same process as anything else.
7. **Status surface**: `ui_server.zig` unwired (TIN-1827); no push alerting (TIN-2061).
8. **Claude coverage**: expiry is readable (`expiresAt` ms) but identity is not readable from the credential → exclusion guard can't protect claude (see §2).
9. The old stay-afloat tick is the opposite shape — one route, do-nothing-if-selectable, one action per tick (`src/main.zig:5703-5737, 6019`) — and is not a substitute.

---

## 4. Blockers & gates before unattended multi-account keepalive is real

| Gate | State | Anchor |
|---|---|---|
| Provider `proactive_refresh` grant | **CLEARED** (claude+codex, #418) — ⚠ memory/Linear "gated on #355 scheduler" is stale; #355 is CLOSED with content merged via #407/#411/#416/#418/#419 | `provider_schema.zig:787-802, 850-864` |
| Per-account operator consent | Permanent gate, default **false** | `config.zig:63`, `secret.zig:66-137`, `pipeline.zig:1003` |
| TIN-2054 Claude posture | **CLEARED & permanent** (tmpdir refusal #404, canonical-keychain refusal #406); residual edge TIN-2104 open | `pipeline.zig:982-1001, 1069-1094` |
| TIN-2059 implementation half | **OPEN — the live frontier**: in-process gate/CAS + engineered warm-vs-live race with provable single-RT spend; R4 partially mitigated at HEAD (warm loop defers to live session's identity flock) but re-entrancy defect stands | TIN-2059 2026-07-02 comment; design PR #396 |
| Exactly-once cross-process smoke | PR **#427 open**, unmerged | — |
| Warm-loop live evidence | **MISSING** — zero `docs/evidence/` runs despite merged code | TIN-2057 comment |
| Golden metric TIN-2057 | Todo; operator-gated on real 4-account enrollment; also needs TIN-2061 alerting + TIN-2063 onboarding | — |
| Claude R2 (managed adapter) | **No plan on the books** closes it — bare-claude dual-writer accepted; store invariant is the only protection for claude proactive refresh | ADR :109-117 |
| TIN-2077 Claude concurrency gate | Blocked on: live HTTP seams (none — zero `std.http` in `src/enroll/`), production engine binder (none), approval wiring (`runReauthRun` stub, `main.zig:5560-5584`), `flowExecutionFor` flip (`orchestrator.zig:157`), TIN-2071 incognito-first (nothing in src/). TIN-1806 verbs are done (#423/#424) | — |
| Unattended reauth | Structurally impossible today on three independent grounds (no binder, stub verb, no live HTTP); shortest path is flow-composition cars 1→2→3→4 codex-only; Claude additionally needs contract amendment | `flow_composition.zig:15-17, 65-75` |
| Never-halt semantics | TIN-1811 + TIN-1812 both **In Review, not merged** (cross-capability degradation, quota wait-and-continue — GH #339 class); TIN-2052 mid-turn flock hang open | — |
| Shared-identity opt-in | Advisory only outside the keepalive pool; identity flock serializes, doesn't prevent, alternating rotations of one RT chain | `provider_schema.zig:858-860` |

---

## 5. Delivery gaps

- **Release**: v0.1.13 real and Latest (⚠ **Linear contradiction**: release-packaging project still "Planned" with "v0.1.13 blocks everything" — TIN-2038 is Done; also the 2026-06-12 recon note "v0.1.13 not cut" predates the cut by hours). `dist/out/` staging lags at v0.1.12. **npm dead at 0.1.9**, formally retired.
- **Packaging SSOT**: not started (TIN-2046/2050 Todo) — v0.1.14 is still hand-cut; Bazel deliberately vestigial (TIN-2105 In Review).
- **The product strangers can install is not the product being built**: install lanes ship the `oauth-mux codex` managed lane; keepalive has **no service packaging** (no launchd/systemd unit; HM module exists in flake — `flake.nix:106-116` — but daemon-service work sits in **Paused** federation-packaging, TIN-1834 — ⚠ partial Linear/repo mismatch). Claude is enroll/refresh substrate with no managed launch (docs explicitly deny an adapter, `docs/spec/broker-mcp-contract-2026-05-03.md:79`).
- **Onboarding**: no `init`/`onboard` to golden-metric topology without insider lore (TIN-2063); docs have exactly one runbook (`docs/runbooks/reauth-accounts-2026-06-01.md`).
- **Observability**: everything pull-only — no push alerting (TIN-2061, golden-metric step-5 gap), no reauth state in preflight/doctor JSON (TIN-1802/1803), no stats export (TIN-2062), silent indefinite lock-wait on 2nd same-account launch (TIN-2049), status UI dead code.
- **Website**: M4 First-Viewport Launch at 85%, target 2026-06-30 **past due**; only incomplete milestone (project `cf175391`).
- **Platform**: Windows runtime unverified (explicitly out of release-packaging scope); Linux Claude store unproven.

---

## 6. Risk register (top-down, with evidence)

1. **RT-family revocation via double-spend** — the founding incident class. Evidence: GH #336/#337 (`token_revoked` from concurrent codex sessions); max-1≡max-4 self-revoke (TIN-2043); sops re-materialized stale `auth.json` revoked the rotated RT system-wide (lab, disabled May 31). Residual exposure: in-process re-entrancy (TIN-2059), claude shared-account keepalive blind spot (§2), Claude R2, unmerged #427 proof.
2. **Canonical-store poisoning** — codex sqlite corrupted for 3 weeks by temp-CODEX_HOME muxxing; fixed structurally in `9be68ae` (#367) (⚠ memory's `bde09d72` hash is **not in this repo's history**). Claude-side guards are refusals, not CAS; a wedged keychain prompt can hold the flock indefinitely (`secret.zig:273-282`).
3. **Browser session bleed** (TIN-2060-proven): account A's claude.com session swallows account B's login → without TIN-2071 incognito-first, mediated 2nd-account Claude reauth is unsafe; nothing in src/ addresses it.
4. **Keepalive halts at first reauth-needed** — dead accounts drain silently; no unattended reauth path exists; no alerting to summon the operator (TIN-2061). Combined with per-process death state (§3.3), unattended operation quietly decays.
5. **Never-halt promise still open at the selector** — `NoAccountSelectable` with a live lesser-capability route one hop away (GH #339; TIN-1811/1812 In Review), plus TIN-2052 mid-turn flock hang-forever.
6. **CI credibility** — vacuous CI hid ~148 never-run tests including a JSON injection in the Claude credential write (#409) and CSRF+stored XSS on the operator UI (#412); remote cross-compile contention cancels (not fails) jobs (`ci.yml:175`, GloriousFlywheel).
7. **Security residuals** — wire-proxy loopback is an unauthenticated token oracle (TIN-2047); keychain secret briefly visible to same-user `ps`.

---

## 7. Linear ↔ repo contradiction ledger

| # | Linear/memory says | Repo truth |
|---|---|---|
| 1 | TIN-1825 Backlog; grant flip "gated on #355 scheduler" | #355 CLOSED; scheduler merged & live-bound (#407/#411/#416/#418/#419); grant flipped at `provider_schema.zig:799-802, 861-864` |
| 2 | release-packaging "Planned", v0.1.13 "blocks everything"; recon "v0.1.13 not cut" | v0.1.13 tagged + GH release Latest 2026-06-12; TIN-2038 Done |
| 3 | TIN-1821 body: "PR #354 parked" | #354 superseded by merged #409 |
| 4 | ide-keepalive project entirely Backlog | Keepalive CLI, runner, grant flip, identity exclusion all merged (B.1/B.2-adjacent); B.3/B.6 genuinely pending |
| 5 | TIN-2059 comment: exactly-once "pinned by permanent smoke (PR #427)" | #427 is an **open** PR at HEAD |
| 6 | Memory: muxxing fix commit `bde09d72` | Hash absent from repo history; structural fix is `9be68ae` (#367) |
| 7 | federation-packaging Paused (incl. HM module TIN-1834) | A home-manager module already ships in the flake (`flake.nix:106-116`, `docs/home-manager.md`) — daemon-service piece is what's actually missing |
| 8 | refresh-serialization scope: fix "must light up broker `credential/refresh`" | Still `notImpl` (`methods.zig:49`); all serialization landed below the broker |
| 9 | TIN-1785 CredentialLock "In Progress" (restarted 2026-07-02) | Blocking flock already on the hot path (TIN-2073 merged); remaining substance is the #427 smoke + in-process gate — ticket scope has silently shifted |

**Shortest critical path to the goal**: merge #427 → TIN-2059 in-process gate + engineered race proof → committed warm-loop evidence (`docs/evidence/`) → resident daemon + launchd/systemd (B.6) + persistent pool state → flow-composition cars 1-4 (codex engine-run reauth) + TIN-2061 alerting → TIN-2071 + TIN-2077 for Claude → TIN-2063 onboarding + service packaging → TIN-2057 golden metric run.
