# Keepalive Push Plan — 2026-07-02

Status: SUPERSEDED 2026-07-11 - DO NOT EXECUTE. Historical snapshot only.
Current authority: `docs/plans/oauth-mux-v0.2-full-broker-foss-program-2026-07-11.md`,
`docs/authority-map.md`, and GitHub #463. Authored 2026-07-02 against HEAD `ba7cdd2`.
Provenance: 21-agent orientation (full ingest of the prompts-enqueue omux corpus
26/39–46/45 + house context; Linear initiative/issue sweep; repo gap map with
file:line anchors) followed by a three-lens plan panel (critical-path /
throughput-max / product-first) adversarially judged and merged.

Historical authority order at capture time: (1) `../prompts-enqueue/context/decision-ledger-2026-07.md`
numbered items (item 12 governs sequencing; a dated correction note mapping its
May TIN ids to live successors accompanies this plan); (2) repo HEAD;
(3) Linear; (4) the prompts themselves (drafts).

Anchor warning: every file:line citation below was verified at `ba7cdd2` and
WILL drift. Verify at your HEAD before editing. Merged ≠ proven: no claim in
this plan upgrades any provider's `proof_status`.

## In-flight reconciliation (2026-07-02, dive-in session)

Three open PRs discovered at dispatch time are the front of the merge train and
supersede parts of the wave-1 lane charters below:

- **PR #427** (`test: exactly-once refresh race smoke`, TIN-1785, scripts-only,
  CI green, mergeable) — IS train slot 1 (W1-1's first merge). W1-1's remaining
  scope: the TIN-2059 in-process re-entrancy gate + engineered race fixture.
- **PR #426** (`build: Bzlmod-only Bazel posture + tinyland.repo.json`,
  TIN-2105; touches `.bazelrc`, `WORKSPACE.bazel`, `tinyland.repo.json`) — IS
  the core of W1-2's shared gate. W1-2's remaining scope: `just
  endpoint-free-check`, `just secrets-scan-dir`, ci-templates latch
  verification, honest TIN-2105 promotion.
- **PR #425** (`docs: foundation packet + provider truth matrix + stale-gate
  corrections`, TIN-1793; corrects the two 2026-06-13 refresh-authority docs) —
  covers part of W1-8's stale-doc reconciliation. W1-8's remaining scope: the
  Linear contradiction-ledger comments, the item-12 correction note, the reauth
  runbook refresh, `docs/spec/provider-repair-contracts.md`.

Train order stands: #427 → gate (#426 + remainder) → TIN-2059 gate PR → …
One CI-triggering PR at a time; docs-only PRs fill gaps.

### Post-merge reconciliation (2026-07-02T19:55Z)

The snapshot above is intentionally preserved as dispatch history, but the
front of the train has moved: PR #427, PR #425, and PR #426 are now merged into
`origin/main` (`d37aed05`). W1-2's remaining scope is therefore only the
gate-remainder branch (`endpoint-free-check`, `secrets-scan-dir`, ci-templates
latch report, and honest TIN-2105 proof-status notes). W1-1's remaining scope
is the TIN-2059 in-process re-entrancy gate. Do not reopen or duplicate the
merged PR work when using this plan.

---

## Scores

| Criterion | Draft 1 (critical-path) | Draft 2 (throughput-max) | Draft 3 (product-first) |
|---|---|---|---|
| (a) Grounding | 8 | 8 | 9 |
| (b) Dependency correctness | 8 | 8 | 9 |
| (c) Safe parallelism | 8 | 9 | 8 |
| (d) Evidence discipline | 9 | 9 | 9 |
| (e) Squeeze resolution | 9 | 8 | 9 |
| (f) Operator value per wave | 7 | 9 | 9 |
| **Total** | **49** | **51** | **53** |

Scoring notes (errors carried into the fix list): Drafts 1 and 2 both silently drop **TIN-1822** (identity dedupe, the open P1 GH #338 max-2==max-1 trap — first rung of the never-halt ladder) and misattach GH #338 to the TIN-1811/1812 lane, which cannot close it; only Draft 3 owns it. Draft 1 runs the warm-loop evidence before the race-proof merges, against the synthesis' "nothing evidence-grade is trustworthy before per-account refresh is race-safe," and defers TIN-2071 past the soak despite it sitting in TIN-2057's blocked-by set (2058–2064, 2070, 2071); it also places the shared gate at train slot 7 despite the gate being every prompt's step 1. Draft 2 stretches item 12 by advancing flow-composition car 2 pre-soak and couples the soak to daemon residency the TIN-2057 DoD does not require; its file-overlap matrix and gate-at-slot-2 train are the best parallelism treatment of the three. Draft 3's gaps are smaller: it documents rather than fixes the vacuous Claude identity exclusion (`warm_runner.zig:98-99`), and silently drops TIN-2044/2103 instead of naming them deferred.

**Verdict:** Draft 3 wins — it is the only draft that owns TIN-1822/GH #338, the only one that lands both TIN-2057 blocked-by items (TIN-2063, TIN-2071) before the soak, and its squeeze resolution ("TIN-2077 is the first justified consumer of the car-by-car allowance") matches ledger-mapping exactly. The merged plan below starts from Draft 3's skeleton, grafts Draft 2's file-overlap matrix, gate-early merge train, and honest-middle re-warm bound, and Draft 1's Claude-exclusion fix, conservative evidence gating, operator-consent front-loading, and exhaustive named-deferral discipline.

---

# THE MERGED FINAL PLAN — omux productionization push

## Executive summary

The July program is ledger item 12 executed literally: the Level-3 evidence lane leads, and its live successors are TIN-2057 (warm-loop evidence, then golden soak), TIN-1813 (never-halt drill), TIN-1823/GH #176 (cassettes), and GH #212 (permutation residue), while the reauth lane (TIN-1805–1808) stays queued and ffi-sdk plus federation-packaging stay parked. The spine is: land the race-proof frontier (PR #427, which is OPEN at HEAD contra the TIN-2059 "permanent" comment, plus the in-process re-entrancy gate) → commit the first-ever `docs/evidence/` warm-loop run → merge the In-Review never-halt semantics (TIN-1811/1812) plus the TIN-1822 dedupe closing P1 GH #338 → land alerting, onboarding, and the TIN-2071 browser-isolation wiring that TIN-2057's blocked-by list demands → run the bounded golden soak on the production path (proactive refresh + repair_state command-owned handoff, no engine-run reauth) → only then advance reauth cars one PR at a time toward TIN-2077. Every lane ends in a dated `docs/evidence/<name>-<UTC>/` dir with a summarizer verdict or a merged PR with Linear proof links; all shared build gates land once in a single-owner lane; the merge train is strictly one CI-triggering PR at a time (remote cross-compile CANCELS parallel jobs); TIN-1851 Model B guards stay untouched, the pre-9be68ae muxxing path stays disabled, and no surface ever says unlimited, bypass, or pooling.

Discipline applying to every lane: verify all file:line anchors at HEAD before editing (lines drift); hedged proof_status vocabulary; evidence dirs print zero tokens/account-ids/paths; every lane extends the single `src/tests.zig` root; never invent TIN ids; never revive Done/Canceled TINs (TIN-2042 stays Canceled; TIN-2113 is in-code with no Linear row — do not create one). Ledger item 16 confirms prompt 26's remainder (Lane W1-1) is in the authorized wave-1 firing set.

---

## Waves

### Wave 1 — fire tomorrow morning (8 lanes; sequential merge slots)

**W1-1 · RACE-PROOF (critical-path head)**
- Objective: close the exactly-once refresh frontier — merge PR #427 (cross-process smoke) and fix the TIN-2059 in-process re-entrancy defect with an engineered warm-tick-vs-live-session race proving single-RT spend.
- Owns: PR #427; TIN-2059 implementation half (in-process gate/CAS in the `repair_state` holder registry where `entry.count += 1` makes the lock process-re-entrant); TIN-1785 closeout-by-rescope (contradiction row 9: flock already landed as TIN-2073; remaining substance IS this work).
- Key files: `src/repair_state.zig` (acquireRepairLockWithMode holder registry), `src/pipeline.zig:741-965` (lock-then-revalidate; freshness re-read is read-then-refresh, not CAS), `src/tests.zig` registration.
- Acceptance: #427 merged; a re-entrancy test that FAILS against the old path; `docs/evidence/refresh-exactly-once-<UTC>/` with summarizer verdict; TIN-2059 + TIN-1785 → Done with proof links.
- Depends on: nothing. Parallel-safe with: all wave-1 lanes (sole owner of repair_state/pipeline). Size: **L**.
- **Dispatch brief:** You own PR #427 (rebase to HEAD and land — it is open, not merged, despite the TIN-2059 comment calling it "permanent") and the TIN-2059 in-process gate: `repair_state.acquireRepairLockWithMode`'s holder registry is process-re-entrant via `entry.count += 1`, so a daemon hosting warm-tick plus broker-materialize for one account can race itself. Build an engineered warm-tick-vs-live-session race fixture proving exactly one RT spend and that a stale refresh result can never overwrite a newer token; verify `pipeline.zig:741-965` anchors at HEAD before editing. You are the sole owner of `src/repair_state.zig` and `src/pipeline.zig` this wave; register tests only in `src/tests.zig`. Do not touch the TIN-1851 Model B guard set or any adapter path. Acceptance: #427 merged, gate PR merged, committed `docs/evidence/refresh-exactly-once-<UTC>/` with a passing summarizer verdict (zero tokens/ids/paths), TIN-2059 and TIN-1785 closed with proof links and TIN-1785 carrying a dated scope-shift note (contradiction row 9).

**W1-2 · DELIVERY GATE (single owner of ALL shared gates — everyone else verifies, never performs)**
- Objective: land the house-mandated build gate exactly once; promote TIN-2105 honestly.
- Owns: WORKSPACE.bazel deletion + Bzlmod-only + registry order (verify state at HEAD first — #420/#421 may have moved it); endpoint-free `.bazelrc`/`.bazelrc.flywheel` + `just endpoint-free-check`; `just secrets-scan-dir` (gitleaks); ci-templates spoke-ci@v2.0.0 / `tinyland-nix` latch; TIN-2105 continuation toward countable executor-backed GF-RBE runs (respecting TIN-2219/2220; never report cache-backed as RBE; "started, not proven" honesty preserved).
- Proof-authority rule (from Draft 1, binding program-wide): wave-1/2 evidence runs execute via just/nix — the current proof authority per justfile:260 — with a dated Bazel-posture divergence note; evidence moves to the TIN-2105 class only after its own executor-backed evidence dir exists.
- Key files: `WORKSPACE.bazel` (delete), `MODULE.bazel`, `.bazelrc*`, `justfile` (gate recipes — W1-2's exclusive property this wave; W1-5's recipe appends after), `.github/workflows/ci.yml`.
- Acceptance: gate PR merged early in train; both new just recipes green; divergence note committed; TIN-2105 comment updated with executor run id if achieved, honest status if not.
- Depends on: nothing. Parallel-safe with: all (zero `src/` overlap). Size: **M/L**.
- **Dispatch brief:** You are the single owner of every shared gate: verify at HEAD whether `WORKSPACE.bazel` still exists (post-#420/#421), delete it if so, confirm Bzlmod-only with registry order tinyland-inc/bazel-registry → BCR, land endpoint-free `.bazelrc*` (env authority: `BAZEL_REMOTE_CACHE`, `GF_BAZEL_SUBSTRATE_MODE`, `BAZEL_REMOTE_EXECUTOR`), add `just endpoint-free-check` and `just secrets-scan-dir`, and latch CI to ci-templates spoke-ci@v2.0.0 with `default_runner_class: tinyland-nix`. No other lane may perform any of this — they verify. Continue TIN-2105 toward a countable executor-backed GF-RBE run (respect TIN-2219/2220; cache-backed is never RBE), but do not block any evidence dir on it: commit a dated divergence note stating just/nix remains proof authority per justfile:260. Acceptance: gate PR merged at train slot 2, recipes green, TIN-2105 Linear comment honest about started-vs-proven.

**W1-3 · NEVER-HALT LANDINGS + IDENTITY DEDUPE**
- Objective: shepherd TIN-1811 (codex-max→codex-mini cross-capability degradation) and TIN-1812 (quota-exhausted wait-and-continue, GH #339) from In Review to merged with real review, AND land TIN-1822 identity dedupe before election — closing P1 GH #338 (max-1≡max-4 zero-selectable trap), which belongs to TIN-1822, not to 1811/1812.
- Owns: TIN-1811, TIN-1812, TIN-1822 (`identity_graph.distinctLiveIdentities` into the election path + golden sha256_12hex test + GH #338 regression fixture), GH #338/#339 closure; TIN-1813 drill-harness prep (execution is wave 2).
- Key files: existing TIN-1811/1812 PR branches, `src/account_pool.zig` (elect :195-203 — verify at HEAD), `src/identity_graph.zig`, fixtures. Wire-proxy retry seams verify-only; TIN-1851-guarded adapter paths untouched.
- Acceptance: three merges (own train slots each) on real, non-vacuous CI; GH #338 and #339 closed with repro-now-passes notes; Linear → Done with proof links.
- Depends on: merge slots. Parallel-safe with: all (account_pool/identity_graph disjoint from W1-1/W1-4 files). Size: **L**.
- **Dispatch brief:** Drive the two In-Review never-halt PRs (TIN-1811 cross-capability degradation, TIN-1812 quota-exhausted wait-and-continue for GH #339) to merge with genuine review — every previously unparked lane hid real bugs behind vacuous CI (~148 never-run tests, including an injection and XSS), so budget for fixes, not rubber stamps. Separately implement TIN-1822: `identity_graph.distinctLiveIdentities` dedupe BEFORE any election/routing/refresh decision, with the golden sha256_12hex test and a regression fixture for GH #338 (real incident: the same AAS-locked OpenAI account presented as two routes). GH #338 closes on TIN-1822, not on 1811/1812. Stage the TIN-1813 drill harness against merged behavior only; drill execution is wave 2. You own `src/account_pool.zig` and `src/identity_graph.zig` this wave; do not touch repair_state, pipeline, or keepalive files.

**W1-4 · SCHEDULER HARDENING + CLAUDE EXCLUSION FIX (soak safety)**
- Objective: make the warm scheduler property-proven, fix the fleet due-cohort alignment, and close the Claude shared-identity blind spot before any 2×Claude soak.
- Owns: TIN-1825 (property tests: saturating `refreshDueAtMs`, max_failures backoff, never-halt dead-skip, degenerate-success guard, anti-naive-scheduler fixture — ticket OPEN despite core merged; its "#355 gate" framing is stale, #355 is CLOSED); stagger/jitter fix for `warm_binding.zig:62-78` (pool build seeds every account into one due-cohort — this IS the "spread refresh load" ask); the Claude identity-exclusion fix — claude declares no `identity_claim_path`, so the `warm_runner.zig:98-99` exclusion is vacuous (test :295 confirms) — wire `oauthAccount.accountUuid` via `src/identity/claude_identity.zig` into the exclusion, recorded under TIN-1825/TIN-2057 comments, **no new TIN invented**; scoped expiry asserts for the two soak providers (claude `.milliseconds`; codex JWT-exp already landed as TIN-2087) — full TIN-2079 (vercel/gemini) rides wave 2's adapter lane.
- Key files: `src/keepalive/warm_scheduler.zig`, `warm_binding.zig`, `warm_runner.zig`, `src/provider_schema.zig` claude block (sole wave-1 editor of this file; the :797-798 comment retirement rides W1-6's evidence PR after this merges), `claude_identity.zig` read-only, `src/tests.zig`.
- Acceptance: merged PR; a test that FAILS against the vacuous-exclusion behavior; TIN-1825 → Done with proof links.
- Depends on: nothing. Parallel-safe with: all (sole owner of `src/keepalive/`). Size: **M**.
- **Dispatch brief:** Harden the warm scheduler for the soak: TIN-1825 property tests (saturating `refreshDueAtMs`, backoff-to-dead at max_failures 8, never-halt dead-skip, degenerate-success guard at :216, plus the anti-naive-scheduler fixture), and add stagger/jitter to pool build — `warm_binding.zig:62-78` currently seeds every account `last_refresh_ms = now`, aligning the whole fleet into one due-cohort. Then close the Claude blind spot: claude declares no `identity_claim_path`, so the shared-identity exclusion at `warm_runner.zig:98-99` is vacuous for Claude; wire the stable identity from `claude_identity.zig` (`oauthAccount.accountUuid`, sha256_12hex) into the exclusion and write a test that fails against today's behavior. Record this fix under existing tickets (TIN-1825 and a TIN-2057 comment) — do not invent a TIN; TIN-2113 (codex exclusion) is landed, do not re-implement it. You solely own `src/keepalive/` and the provider_schema claude block this wave; assert claude expiry units (`.milliseconds`) while there.

**W1-5 · CASSETTES (evidence-chain item b)**
- Objective: land the wire-cassette recorder/replayer so real Codex wire behavior is recorded once and replayed offline in CI with zero spend.
- Owns: TIN-1823 / GH #176 (re-homed from TIN-950 per its 2026-06-12 reconciliation).
- Key files: net-new recorder/replayer module under `src/`, cassettes under `test/fixtures/` (neutralize-on-disk + reconstruct-in-memory per fixture_redaction — the scanner forbids token markers on disk), `just smoke-codex-cassette-replay` (appends after W1-2's gate PR), one `src/tests.zig` import.
- Acceptance: replay smoke green offline; recorded-once cassette committed redacted; run documented in `docs/evidence/cassette-recorder-<UTC>/`; TIN-1823 → Done, GH #176 closed.
- Depends on: one live recording window (piggybacks W1-6's scheduled account window). Parallel-safe with: all (net-new files). Size: **M**.
- **Dispatch brief:** Build the TIN-1823 wire-cassette recorder/replayer (GH #176): record real Codex wire behavior once during the shared operator account window, then replay offline in CI with zero spend. Cassettes live under `test/fixtures/` using the mandatory technique — neutralize-on-disk, reconstruct-in-memory — because the fixture_redaction scanner forbids token markers on disk (see PR #357 lineage). All files are net-new; your only shared-file touches are one `src/tests.zig` import and a `just smoke-codex-cassette-replay` recipe that rebases onto W1-2's justfile after the gate PR merges. Acceptance: replay green offline, redacted cassette committed, `docs/evidence/cassette-recorder-<UTC>/` documented, TIN-1823 Done and GH #176 closed with proof links.

**W1-6 · WARM-EVIDENCE (first flagship dir; TIN-2057 stage 1)**
- Objective: convert "keepalive merged, not proven" into the first committed warm-loop evidence dir — the exact residue ledger item 12 names.
- Owns: TIN-2057 stage-1 evidence; retirement/hedging of the `provider_schema.zig:797-798` "Live-proven" comment (comment-only edit riding this PR, after W1-4 merges).
- Protocol (hard rules): live run fires **only after W1-1's two merges** (#427 + the TIN-2059 gate) — nothing evidence-grade is trustworthy before per-account refresh is race-safe; bounded foreground run via existing `oauth-mux keepalive` CLI (`src/main.zig:366-411`), no src changes; 2×Codex distinct identities, consent-gated (`allow_proactive_refresh`, default false); Claude accounts join only if a distinct-identity pre-flight (accountUuid check) passes — shared-identity Claude pairs are forbidden until W1-4's exclusion fix is merged; zero concurrent live sessions on participating accounts during the window; Claude caveats documented honestly (no quota signal, no adapter, refresh-only claim, `local_live_proven` cap).
- Acceptance: committed `docs/evidence/keepalive-warm-loop-<UTC>/` with passing summarizer verdict, zero tokens/ids/paths; TIN-2057 stage-1 comment with proof link (ticket stays open — golden soak remains).
- Depends on: W1-1 merged; operator consent flags + one quiet account window (shared with W1-5's recording). Size: **M** (operational + docs-only commit).
- **Dispatch brief:** Commit the first-ever warm-loop evidence dir. Wait for both W1-1 merges (#427 and the TIN-2059 in-process gate) before any live run, then execute a bounded foreground `oauth-mux keepalive` run on already-enrolled accounts: 2×Codex with distinct identities, consent flags set by the operator, Claude accounts only if the accountUuid distinct-identity pre-flight passes, and a hard rule of zero concurrent live sessions on participating accounts for the window. Your commit is docs-only plus one comment edit: the evidence dir `docs/evidence/keepalive-warm-loop-<UTC>/` with summarizer verdict and zero tokens/account-ids/paths, and retirement of the unproven "Live-proven 2026-06-14" comment at `provider_schema.zig:797-798` (rebase after W1-4, which owns that file's claude block this wave). Claude claims stay capped at refresh-evidence with the no-quota-signal and no-adapter caveats stated verbatim. Update TIN-2057 with a stage-1 proof link; do not close it.

**W1-7 · SITE TRUTH PHASE 1 (separate repo — free parallelism, outside the merge train)**
- Objective: make omux.xoxd.ai a passive truth consumer at v0.1.13 with no 404s and a documented real deploy lane (M4 is past due; TIN-734 In Progress).
- Owns: TIN-734 phase 1 — version sync 0.1.7→0.1.13 across 6 copy surfaces + bootstrap spec (0.1.6) + CI version-parity check failing on drift; `static/og-image.png`; install.sh 404 fix; deploy-lane truth doc (GH-Pages deploy-pages@v5 + Cloudflare DNS-only gray-cloud divergence) + `/canary` post-deploy gate; federation stays PLANNED-only prose (`static/pulse/` placeholder unchanged; signed static snapshots are NOT federation); cmus CNAME scrub. Provider-matrix regen **deferred to wave 3** (needs W2-6's refreshed matrix). Site package.json 0.0.1 is a distinct field — don't touch.
- Key files: tinyland-inc/omux.xoxd.ai — zero oauth-mux CI contention.
- Acceptance: deployed + canary green; parity check red-on-drift proven; TIN-734 progress comment with links.
- Depends on: nothing. Size: **S/M**.
- **Dispatch brief:** In the tinyland-inc/omux.xoxd.ai repo (never this one), sync every copy surface from 0.1.7 (and the bootstrap spec's 0.1.6) to 0.1.13 and add a CI version-parity check that fails on drift; fix the 404ing install.sh reference and the missing `static/og-image.png`; document the real deploy lane (GH-Pages deploy-pages@v5 with Cloudflare DNS-only gray-cloud — a noted divergence from the house CF-Pages assumption) and gate deploys with gstack `/canary`. Federation remains PLANNED-only prose; do not touch `static/pulse/` beyond its contract-shape placeholder and do not touch package.json's 0.0.1. Defer the provider-matrix regen to wave 3 — it consumes the wave-2 adapter-truth matrix. Public copy stays operator-tool/protected-preview shaped; nothing may say unlimited, bypass, or pooling, and nothing weaker than live_proven may render live.

**W1-8 · HYGIENE (docs/Linear/memory only — full detail in Hygiene batch)**
- Objective: reconcile Linear, memory, and stale docs to repo truth so no wave-2 lane inherits a stale premise.
- Owns: the 9-row contradiction ledger; the item-12 dated correction note; three stale 2026-06-13 docs + the reauth runbook; memory corrections; TIN-2077 sequencing comment.
- Acceptance: docs-only PR(s) merged in train gaps; all Linear comments posted dated.
- Depends on: nothing. Size: **S/M**.
- **Dispatch brief:** Execute the hygiene batch exactly as specified below: dated correction comments on all 9 contradiction-ledger rows, the ledger item-12 correction note mapping TIN-1517→950→951(→916) to their live successors (TIN-2057 / TIN-1813 / TIN-1823+GH #176 / GH #212) per the ledger's own dated-note rule, superseded-by headers on the three stale 2026-06-13 refresh-authority docs, a refresh of `docs/runbooks/reauth-accounts-2026-06-01.md` against the #423/#424 verb surface, and the four memory corrections. Never silently rewrite; never revive Done/Canceled TINs; do not create a Linear row for TIN-2113. Your PRs are docs-only and slot into merge-train gaps.

### Wave 2 — operator story + evidence spine (fires as wave-1 merges clear)

**W2-1 · DRILL EXECUTION (evidence-chain item c)** — Run TIN-1813 against merged 1811+1812+1822: cross-capability degradation + quota continuation drill, retiring the lab-wrapper cascade (nix/home-manager/codex.nix). Substrate: the TIN-2105 executor-backed class if its promotion evidence exists by then; otherwise just/nix with the dated divergence note (per W1-2's rule). Output: `docs/evidence/never-halt-cross-cap-quota-drill-<UTC>/`. Depends: W1-3. Size: **M**.

**W2-2 · ALERTING + STATS + LOOPBACK TOKEN (TIN-2057 blocked-by set + oracle closure)** — TIN-2061 push-alert channel for reauth-needed (repair_state `appendEvent`) and keepalive-failure (warm_scheduler TickReport) transitions: fires off already-recorded state, transport credential by NAME only, socket-independent (never coupled to the experimental daemon stub); TIN-2062 identity-keyed stats export to the in-repo coye.ai-shaped fixture (Codex quota rich, Claude honestly absent, never fabricated); TIN-2047 per-session loopback auth token (GH #376 — closes the wire-proxy unauthenticated token oracle; gates every future 127.0.0.1 surface); TIN-2044 retention caps and TIN-2103 deterministic `target_failed` as small in-lane closers. Sequenced after W1-1 merges (repair_state read side). Acceptance: fixture-fired alert proof + no-spend contract tests; token required on every loopback surface; Linear Done ×4 + GH #376 closed. Size: **M/L**.

**W2-3 · STRANGER ONBOARDING (both TIN-2057 blocked-by items)** — TIN-2063: real `init --interactive` guided four-account (work/personal × Claude/Codex) cold-start with zero baked insider topology, honoring the account-enrollment contract (Visibility → Admission → Mutation); Codex device-code handoff (enrollment never runs `codex login`); Claude scaffold + hand off to vendor `claude /login`. TIN-2071: wire `browser_launch.zig` incognito-first per-account ephemeral profile (tier1_print / tier2_ephemeral_chrome, profile create/delete, no secret in argv) — **mandatory before any 2nd-Claude-account enrollment** (session bleed is live-verified; the private-window procedure is the fallback, not the plan). Proof: `just first-run-e2e` cold run enrolling four accounts; account-2 Claude in a distinct ephemeral profile with no bleed. Implementation-update log appended to the enrollment contract. Depends: main.zig merge slot after W2-4. Size: **L**.

**W2-4 · HONEST STATUS (operator UX truth)** — TIN-2049 bounded "waiting on `<account>` (`<reason>`)" notice + readiness that never mislabels a live session as stalled; TIN-1802 reauth job state from repair_state (production path, NOT the unwired engine) into doctor/preflight/route JSON; TIN-1803 route-state + resume-index health into `accounts list`/`route explain` (qa-handoff vocabulary; never assert a specific route currently selectable). No-spend contract tests throughout. Development starts wave 1; merges after W1-1 (repair_state API) and W1-3 (main.zig sections). Size: **M**.

**W2-5 · PACKAGING SSOT (release-packaging only — NOT federation-packaging)** — TIN-2046 hermetic Bazel-module packaging SSOT replacing `scripts/release-local.sh` inline config; TIN-2050 all lanes derived at 0.1.13 including nix flake 0.1.7→0.1.13, NET-NEW darwin `.pkg` (pkgbuild), `just registry-dry-run` gate, npm stays retired, no `.app`/`.dmg` claims ever; TIN-1830 launchd/systemd units emitted FROM the SSOT with install/enable/disable QA on macOS AND linux. Copy constraint: no packaging or docs surface advertises keepalive beyond committed evidence — service units ship as substrate for wave 3, not as a "keepalive works" claim. TIN-1832/1833/1834 stay **PARKED** — "packaging SSOT" must not smuggle the federation-packaging nix trio in. Depends: W1-2. Size: **L**.

**W2-6 · ADAPTER TRUTH + GH #212 RESIDUE (evidence-chain item d)** — TIN-2104 keychain suffix-derivation fix (default `~/.claude` dir = base service, suffixed = derived; unit tests vs TIN-2060 shape); full TIN-2079 expiry-unit verification (vercel/gemini epoch-ms; claude/codex asserts landed in W1-4/TIN-2087); TIN-1820 Claude CredentialMaterializer shape (today only `chatgpt_auth_tokens`, `methods.zig:508,520`) + no-raw-token-bytes boundary test; TIN-1824 dated Claude quota-reset test plan + first recorded observation windows (GH #212; passive, no-spend, live probes only behind `OMUX_LIVE_QA_CONFIRM`). NOT TIN-1821 (reauth-adjacent — car territory; and #354 is never revived). Refreshed truth matrix feeds wave 3's site regen. Size: **M**.

### Wave 3 — golden soak, then queued cars as needed

**W3-1 · GOLDEN SOAK (TIN-2057 GOLDEN — third flagship dir)** — 2×Claude + 2×Codex work/personal, stranger-to-keepalive via W2-3 onboarding, **bounded attended foreground soak** (the DoD per ledger-mapping is warm refresh + handoff protection + alerting + stats — daemon residency is NOT required and not claimed), ~75%-lifetime proactive refresh, alerting + stats live from W2-2, reauth-handoff protection per the squeeze resolution. Output: `docs/evidence/keepalive-golden-soak-<UTC>/` with passing summarizer verdict, zero tokens/ids/paths, and explicit out-of-window statements (re-warm-without-restart = TIN-1828, deferred; unattended reauth = none; residency = W3-4). Depends: W1-1, W1-4, W2-2, W2-3. Size: **L** (orchestration + evidence).

**W3-2 · REAUTH CARS (car-by-car, item-12 allowance, post-soak-start)** — TIN-1804 single-flight reauth queue first (in-proc mutex + flock + TTL reaper off the repair_state idiom); then flow-composition car 2 (live `std.http` loopback seam — today zero `std.http` in `src/enroll/`; codex device_code only; `flowExecutionFor` stays `.command_owned`); then car 3 (approval wiring so `runReauthRun` stops emitting `engine_run_available:false` unconditionally) — each car a separate PR carrying a written need note citing item 12. Claude stays vendor-CLI/command-owned throughout; no PR #354 revival; no provider-boundary amendment. Size: **M** per car.

**W3-3 · TIN-2077 CLAUDE CONCURRENCY GATE (conditional — explicitly not a July commitment)** — 2 live Claude accounts concurrent, one mediated command-owned reauth, zero disturbance to the other session; `docs/evidence/claude-concurrent-handoff-<UTC>/`. TIN-2077 is the first justified consumer of the car-by-car allowance; hard-gated on W2-3's TIN-2071 wiring + W3-2 cars. If cars don't advance far enough, report honestly as not-July. Size: **M/L**.

**W3-4 · RESIDENCY + STATUS BOARD (post-soak)** — TIN-1827 wire `ui_server.zig` behind UiListener (loopback-only, exact-match `isLoopbackHost`, TIN-2047 token-gated, structural redaction); TIN-1831 production socket (flip `production_supported`/`hosts_stay_afloat` ONLY on evidence); persistent pool/backoff state so a restarted loop remembers dying accounts; TIN-2052 try-lock + re-elect mid-turn. Safe only post-TIN-2059 gate (in-process co-residency). Size: **L**.

**W3-5 · SITE MATRIX REGEN** — `just regen-providers` from W2-6's matrix; Codex-only-live test; no-blocked-rendered-live test; README Bedrock/Azure phantom rows + 7-vs-10 fix; keep NotClaimed boundaries. Depends: W2-6. Size: **S**.

**W3-6 · GH #212 OBSERVATION CLOSEOUT** — conclude the quota-reset record started in W2-6; only after this may any Claude-quota claim exist anywhere. Size: **S**.

### Parked and deferred (named, per precision rules)

**PARKED (require a new ledger decision):** prompt 46 / ffi-sdk entirely (TIN-1798/1799/1800/1801 + embedder); federation runtime (TIN-1835/1836/1837); federation-packaging nix trio (TIN-1832/1833/1834).
**Explicitly deferred, off the July spine (dated notes where a project acceptance is touched):** TIN-1826 broker `credential/refresh` (still `notImpl` at `methods.zig:49`; dated note on the refresh-serialization project citing item 12); TIN-1828 (behind TIN-1805 cars); TIN-1808 web UI stepper; TIN-1829 IDE seams; TIN-1818/1819/2078 de-codexing; TIN-1821 Claude reauth adapter maturation; TIN-2045 chooser-resume arch; TIN-2040 proxy perf; TIN-2051 age bech32; remaining TIN-2079 surface beyond the four verified providers; Windows runtime verification; Linux Claude store proof (documented as known-open edges in soak evidence where relevant).

### File-overlap matrix (wave 1)

| Lane | repair_state/pipeline | src/keepalive/ + provider_schema(claude) | account_pool/identity_graph | cassette module/fixtures | main.zig | justfile/bazel/CI | docs/evidence | site repo |
|---|---|---|---|---|---|---|---|---|
| W1-1 | **OWNS** | – | – | smoke only | – | – | own dir | – |
| W1-2 | – | – | – | – | – | **OWNS** | divergence note | – |
| W1-3 | – | – | **OWNS** | #338/#339 fixtures | possible verb touch → dedicated slot | – | – | – |
| W1-4 | – | **OWNS** | – | – | – | – | – | – |
| W1-5 | – | – | – | **OWNS** | – | 1 recipe, after W1-2 | own dir | – |
| W1-6 | – | comment-only, after W1-4 | – | – | – | – | **flagship dir** | – |
| W1-7 | – | – | – | – | – | – | – | **OWNS** |
| W1-8 | – | – | – | – | – | – | **OWNS spec/runbooks** | – |

`src/tests.zig` registration lines: every code lane appends one import; trivial rebase-at-train-head conflicts, accepted. Wave-2 main.zig contention (W2-3/W2-4): section ownership declared at dispatch, train-serialized, rebase-keep-all-imports, no lane holds two open PRs.

---

## Merge train

Remote cross-compile has no concurrency group; parallel PRs get CANCELLED, not failed. All lanes develop on branches concurrently; exactly one CI-triggering PR at a time; rebase at train head before each slot; docs/evidence-only PRs slot into CI gaps; W1-7 rides the site repo fully out-of-band.

**Wave 1:** (1) **PR #427** (open now; rebase, land first) → (2) **W1-2 gate PR** (early so every later PR verifies it and rework is cheap) → (3) **TIN-2059 in-process gate + engineered race** (critical path clear; W1-6 live run authorized) → (4) **TIN-1811** → (5) **TIN-1812** → (6) **TIN-1822 + GH #338 fixture** → (7) **W1-4 scheduler + jitter + Claude exclusion** → (8) **W1-5 cassettes** → (9) **W1-6 warm-loop evidence dir + provider_schema comment retirement** → (10) **W1-8 hygiene batch** (gap-filler throughout).

**Wave 2:** W2-2 (2047 → 2061 → 2062 + 2044/2103) → W2-4 (2049/1802/1803) → W2-3 (2063 → 2071) → W2-6 (2104/2079/1820 + 1824 plan) → W2-1 drill evidence dir → W2-5 SSOT (largest, most rebase-tolerant — bazel/dist files, last).

**Wave 3:** W3-1 soak evidence → W3-2 cars strictly one PR at a time (1804 → car 2 → car 3, each with item-12 note) → W3-3 2077 evidence → W3-4 residency → W3-5/W3-6 (site repo / docs, out-of-band or tail).

Rules: a lane not at train head keeps building locally against the train tip; no lane opens a second PR while its first is in CI; every unparked In-Review PR gets real review (vacuous CI previously hid ~148 never-run tests).

---

## Reauth squeeze resolution

**Choice: bounded soak on the production path that exists today — proactive-refresh-only + repair_state command-owned handoff. No TIN-1805 scoping into the July evidence window.** (All three drafts converged here; this is adopted as binding.)

Justification: (1) Ledger item 12 queues TIN-1805–1808 behind the evidence chain; pulling 1805 forward inverts operator-adjudicated sequencing while a production alternative exists at HEAD. (2) "Minimal TIN-1805" is a fiction — unattended engine-run reauth is structurally impossible at HEAD on three independent grounds: zero production engine callers (`ReauthOrchestrator.init` appears only in tests), `runReauthRun` unconditionally emits `engine_run_available:false` (`main.zig:5560-5584`), and there is zero `std.http` in `src/enroll/`; the true minimum is flow-composition cars 1–3, i.e. the whole front of the queued lane. (3) Command-owned handoff IS the doctrine (in-agent-reauth-handoff contract; mediator never runs logins; Claude stays vendor-CLI regardless). (4) The handoff substrate is real and merged: single-flight repair lock, TIN-1806 verbs + `OMUX_REAUTH_*` env + readiness (#423/#424), repair_state `appendEvent` feeding W2-2 alerting, and W2-4 threading repair_state into operator-visible JSON so the handoff is observable, not silent.

**"Reauth-handoff protection" for TIN-2057 therefore means:** when proactive refresh exhausts (max_failures), the account transitions to needs_reauth via repair_state; the TIN-2061 alert fires off the recorded transition; the pool skips the account (never halts); and the handoff names the command-owned next action (vendor `claude /login` / codex device-code). Operator-in-the-loop, mediated, never silent.

**TIN-2057 acceptance satisfiable in waves 1–3:** multi-account proactive refresh at ~75% lifetime; never-double-rotate (including W1-4's Claude exclusion fix); dead-account skip / pool never halts; alerting + stats (W2-2); stranger-to-keepalive onboarding (W2-3); handoff protection as defined above.

**Explicitly deferred, documented in the soak evidence as out-of-window:** re-warm-without-restart after mid-soak death (TIN-1828, which depends on TIN-1805 and stays queued — the honest middle is pool re-admission after operator vendor-CLI repair on the next bounded run, plus natural in-backoff-window recovery if it occurs; neither is claimed as TIN-1828); unattended/engine-run reauth entirely; daemon residency (W3-4, post-soak).

**TIN-2077 consequence:** formally wave 3, conditional, not a July commitment. Its prerequisites split cleanly: TIN-2071 is a TIN-2057 blocked-by item and lands in W2-3 outside the queued lane; the binder/approval prerequisites are exactly the W3-2 cars, advanced one PR at a time post-soak, each citing item 12 — making TIN-2077's evidence dir the first justified consumer of the car-by-car allowance. Its Linear ticket gets a dated sequencing comment now (W1-8) so nobody treats it as a July gate.

---

## Hygiene batch (W1-8, docs tail in W2)

**Ledger item 12 correction note (binding pattern: dated note citing the item number, never silent rewrite):** append to the decision ledger: item 12's four named TINs (1517 → 950 → 951, gating 916) were all Done by 2026-05-19; the ids name the completed May Codex Level-3 stage, whose live successors are TIN-2057 (warm-loop evidence + golden soak), TIN-1813 (drill), TIN-1823/GH #176 (cassettes), GH #212 (permutation residue). Cross-link the same note from TIN-2057 and from any prompt/Linear framing sequencing reauth/ffi-sdk/federation ahead of the evidence chain.

**Linear contradiction ledger (gapmap §7, all 9 rows — dated comment with repo proof link each):**
1. TIN-1825: #355 is CLOSED; scheduler merged and live-bound (#407/#411/#416/#418/#419); grant flipped (`provider_schema.zig:799-802, 861-864`); re-scope to the open property-test work (W1-4).
2. release-packaging project: v0.1.13 tagged + GH release Latest 2026-06-12; TIN-2038 Done recorded terminal; project off "Planned".
3. TIN-1821: PR #354 superseded by merged #409 (and never revived).
4. ide-keepalive project: keepalive CLI/runner/grant-flip/identity-exclusion merged; B.3/B.6 genuinely pending; per-ticket states updated.
5. TIN-2059: "#427 permanent smoke" corrected — #427 open at HEAD; updated again on W1-1 merge.
6. Memory row — muxxing fix hash: `bde09d72` is absent from this repo's history; the structural fix is `9be68ae` (#367) (correction lands in memory, noted on the ledger row).
7. federation-packaging: the flake already ships an HM module (`flake.nix:106-116`); the genuinely missing parked piece is the daemon-service module (TIN-1834).
8. refresh-serialization project: broker `credential/refresh` still `notImpl` (`methods.zig:49`); serialization landed below the broker; acceptance clause deferred to TIN-1826 with a dated note citing item 12 — transferred, not silently dropped.
9. TIN-1785: scope silently shifted — flock landed as TIN-2073; remaining substance re-homed to #427 + the in-process gate; closed via W1-1 with a dated comment.
Plus: TIN-2077 dated sequencing comment (wave 3, post-soak, car-by-car per item 12). Never create a row for TIN-2113; never revive Done/Canceled TINs (TIN-2042 npm stays Canceled); the Claude-exclusion fix rides existing tickets — no invented ids.

**Stale-doc reconciliation (dated superseded-by notes, never rewrites):** `docs/spec/dual-writer-refresh-designation-2026-06-13.md`, `docs/spec/refresh-authority-adr-trace-2026-06-13.md`, `docs/spec/provider-repair-contracts.md` — all still say "grant flip BLOCKED", pre-dating #417/#418: add dated headers citing the PRs; forbid citation in either direction until reconciled. Refresh `docs/runbooks/reauth-accounts-2026-06-01.md` against the #423/#424 command-owned verb surface, noting `engine_run_available:false` is current truth. Append implementation-update logs to the enrollment and reauth-handoff contracts when W2-3 and W3-2 land.

**Memory corrections (auto-memory):** codex-muxxing memory: fix hash `bde09d72` → `9be68ae` (#367); Model B shipped as the v0.1.13 default (TIN-1851 Done), so the remaining forbidden path is the legacy `shared_canonical` opt-in. Refresh-authority memory: grant flip DONE (#418), #355 closed — no longer "gated"; new frontier is the TIN-2059 in-process gate (closed by W1-1). Recon-2026-06-12 memory: "v0.1.13 not cut" superseded within hours — shipped 2026-06-12. Reauth-orchestrator memory: append that at HEAD the engine has zero production callers, approval still cannot invoke it, and #427 was open as of 2026-07-02 (update on merge).

---

## Risks

1. **Live RT-family double-spend during evidence runs** (the founding incident class: GH #336/#337; max-1≡max-4 self-revoke; sops re-materialization). Mitigation: W1-1 heads the merge train and the warm-loop run is hard-gated on both its merges; all live runs bounded + attended, zero concurrent sessions on participating accounts, distinct-identity pre-flight; W1-4 closes the Claude exclusion blind spot before any 2×Claude soak; auth shadow backups verified before each window; consent defaults false.
2. **CI cancellation wipes out parallel work** (remote cross-compile CANCELS on contention). Mitigation: strict single-PR merge train; gate PR at slot 2 so reworks are cheap; lanes file-disjoint per the ownership matrix (a dispatch-time contract in every lane brief); docs/evidence PRs held as gap-fillers; site work exiled to its own repo.
3. **Operator-availability bottleneck** (consent flips, real 4-account enrollment, keychain prompts, quota observations; a wedged keychain prompt can hold a flock — `secret.zig:273-282`). Mitigation: front-load all operator-attended asks into two scheduled windows (wave-1 warm-run/recording day shared by W1-5 and W1-6; wave-3 soak start); everything else fixture/cassette-driven; TIN-1824 observations are passive.
4. **TIN-1811/1812 (and other unparked In-Review PRs) hide real bugs** — every previously unparked lane did, behind vacuous CI (~148 never-run tests including an injection and XSS). Mitigation: W1-3 is review-first with fix budget; the TIN-1813 drill builds only against merged behavior, so a slipped merge slips the drill, not the soak.
5. **Truth-posture/TOS overstatement pressure** — a committed soak dir will tempt "Claude keepalive works" and "never hit a login wall" copy. Mitigation: every evidence summary uses proof_status vocabulary with summarizer verdict; Claude claims capped at refresh-evidence until W3-1 + W3-3 commit (no quota signal until GH #212 closes, no adapter, TIN-2077 unproven); site regen mechanically derived from the in-code proof_status enum, no-blocked-rendered-live CI test; nothing anywhere says unlimited, bypass, or pooling; public surface stays operator-tool/protected-preview per house posture.
6. **Scope creep into parked/queued lanes** ("needed for the soak" smuggling in engine-run reauth, FFI, or the federation nix trio). Mitigation: the squeeze resolution is binding; every W3-2 car PR requires a written need note citing item 12; lane charters enumerate owned TINs exhaustively — anything else is out of charter; W2-5 explicitly excludes TIN-1832/1833/1834.
