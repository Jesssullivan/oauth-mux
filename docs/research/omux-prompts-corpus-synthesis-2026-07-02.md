> Dated synthesis of the ../prompts-enqueue omux fable-prompt corpus (26, 39-46, 45) + house context, 2026-07-02. The prompts are DRAFTS; decision-ledger-2026-07 item numbers override. Companion to `docs/plans/keepalive-push-2026-07-02.md`.

# omux / oauth-mux — Definitive Orientation
**Synthesized 2026-07-02 from prompt corpus (26, 39–46, incl. 45) + house context brief + peripheral cross-links. This document is the internalization target for the multi-workflow productionization push.**

Authority order for anything below: (1) decision-ledger-2026-07 numbered items override everything older; (2) repo HEAD (Jesssullivan/oauth-mux) is runtime truth; (3) the prompts are *drafts* — DAG-shaped work orders whose framings the ledger may have superseded; (4) the three 2026-06-13 refresh-authority decision docs are STALE at HEAD and must never be cited in either direction.

Post-merge note (2026-07-02T19:55Z): PR #427, PR #425, and PR #426 have merged
since this corpus snapshot was written; current `origin/main` is `d37aed05`.
The shared build-gate base is no longer to be re-performed. Remaining gate work
is the stacked remainder (`endpoint-free-check`, `secrets-scan-dir`, ci-template
latch report, and TIN-2105 proof-status honesty), plus the TIN-2059 in-process
refresh gate.

---

## 1. Product vision — "keepalive to the masses" in one page

omux (the oauth-mux Zig runtime) is a **race-safe, embeddable, resumable multi-harness OAuth broker** for AI-harness subscriptions. The one-sentence product: *an operator enrolls their own paid Claude/Codex accounts once, runs `oauth-mux keepalive`, and never hits an "unauthorized / please log in" wall mid-coding-turn again — even after 12 hours away, even across concurrent sessions, even when a token family rotates or an account dies.*

The vision decomposes into five promises, each with a named proof bar:

1. **Stay afloat** — a warm loop proactively refreshes every consenting account before expiry (refresh at 75% of token lifetime), skips dead accounts rather than blocking the pool, and never double-rotates a shared refresh-token family. Proof bar: the **golden soak** — 2×Claude + 2×Codex (work/personal), stranger-to-keepalive, bounded soak, committed `docs/evidence/keepalive-golden-soak-<UTC>/` with a passing summarizer verdict (TIN-2057, GOLDEN, Urgent).
2. **Never halt** — quota exhaustion or a dead account degrades or waits; it never strands the operator. Success metric is **Level-3 `next_turn_seamless`** per `docs/spec/broker-mcp-contract-2026-05-03.md §4`: on quota exhaustion the next turn lands on a fresh account **in the same process — no restart, no prompt**. Restart is explicitly NOT a product behavior (supervised-harness-restart contract is OBSOLETE).
3. **Repair, don't lose** — when refresh finally fails, a single-flight, **mediated, command-owned** re-login handoff repairs the session (never a silent engine-run browser login; Claude login stays vendor-CLI `claude /login`), and the account re-warms without process restart.
4. **Embed anywhere** — the broker core sits behind typed seams so a frozen stdio JSON-RPC `surface_version:1` (`oauth-mux mcp`) and a `libomux` C-ABI expose the same pure core, with the hard invariant that **no raw token bytes ever cross the boundary** (opaque `CredentialHandle`s only, material via the `CredentialMaterializer` vtable).
5. **Tell the truth** — every provider claim is keyed to the in-code `proof_status` enum (`live_proven | local_live_proven | public_live_proven | needs_operator_proof`); Codex is the ONLY `live_proven` provider; site, packages, and docs may never advertise beyond committed evidence.

"To the masses" is delivery-side: cold-clone stranger → `init --interactive` → four accounts enrolled with zero baked insider topology; installs via 6 tarballs / curl / rpm / deb / brew / nix / NET-NEW darwin `.pkg`, all derived from ONE hermetic Bazel packaging SSOT, all reconciled to v0.1.13; keepalive installable as a first-class launchd/systemd service.

**Hard framing constraint (TOS, load-bearing everywhere):** this is a stay-alive story about the operator's **own authorized accounts**. No surface may ever say or imply *unlimited, rate-limit bypass, anti-detection, resale, hosted proxy, or credential pooling* (`docs/policy/tos-posture-2026-05-05.md:49-78`; OpenAI TOS is heavy on Codex, the only live-proven provider). House posture also caps "masses": omux is absent from the ecosystem map and golden objectives; any public surface inherits paid-pilot/protected-preview doctrine, never public self-serve SaaS. "A domain held is not a product surface."

**Headline trap the whole corpus is built around:** the keepalive warm loop is **merged, not proven**. `oauth-mux keepalive` is wired (src/main.zig:366, PR #417); the `proactive_refresh` grant is flipped and consent-gated on `allow_proactive_refresh` (PR #418, provider_schema.zig:792-802); but the "Live-proven 2026-06-14 keepalive" line at provider_schema.zig:797-798 is a **code comment with no `docs/evidence/**` directory behind it**. The deliverable of the entire arc is committed evidence, not code comments.

---

## 2. The never-halt / keepalive model

### 2.1 Warm loop mechanics (prompt 39)
- Pipeline at HEAD: `runKeepalive` (main.zig:366) → `warm_runner.enumeratePool` → `warm_binding.buildPool` → `warm_scheduler.Scheduler` → `warm_binding.runLoop`.
- Pure core `warm_scheduler.zig` (no I/O, no own clock): `refresh_percent:75` (refresh before expiry), `max_failures:8` backoff, **never-halt dead-account skip** (a dead account is skipped, never blocks the pool), **degenerate-success guard** (refresh returning expiry ≤ issue is treated as failure, :216). TIN-1825 hardens this with property tests (saturating arithmetic in `refreshDueAtMs`, plus a fixture that would fail a naive refresh-everything-unconditionally scheduler).
- Refresh is strictly **consent-gated per account** (`allow_proactive_refresh:true`); `pipeline.refreshAccount` is currently safe only by consent gate (`not_admitted` unless grant + consent) — the canonical serialized broker path doesn't exist yet (see 2.3).
- **Shared-identity exclusion is ALREADY LANDED — do not re-implement** (TIN-2113, PR #419, warm_runner.zig:129-137): duplicate OAuth identities are excluded via `ig.duplicateCollisions` so a shared refresh-token family is never double-rotated and a duplicate slot is never mistaken for failover. No Linear row exists for it.

### 2.2 The auth-singleton problem and its treatment
The corpus treats "one login clobbers all live sessions" as a *family* of singleton defects, each with a named fix:

| Singleton layer | Defect | Fix / owner |
|---|---|---|
| Refresh write path | `broker_loader.refreshCodexAccountAuthFile` (~:387) takes NO lock → concurrent sessions double-spend a single-use rotating RT (the codex-refresh-token-race incident, GH #336 / PR #337) | **CredentialLock**: per-`provider:account` blocking flock on the write path, factored from existing `acquireRepairLockBlocking` (repair_state.zig:513) — TIN-1785, prompt 26 |
| Dual writers under RT rotation | stale refresh result could overwrite a newer token | TIN-2059 dual-writer fixture proving stale can NEVER overwrite newer ("hardest golden-metric problem") — prompt 26 |
| Child harness sessions | child can clobber broker-owned auth state | flip `shouldPreserveChildAuth` to **broker-owned-only** single-writer — TIN-1786, prompt 26 |
| Multiple refresh callers (warm loop, reauth trigger, FFI) | each has its own path today | ONE serialized broker-owned `credential/refresh` all callers inherit; retire `not_implemented` at broker/methods.zig:49 — TIN-1826, prompt 39 |
| Claude macOS credential store | os-keystore-singleton, "3 singleton layers"; creds in login-keychain service `Claude Code-credentials-<sha256(CLAUDE_CONFIG_DIR)[:8]>` (verified, TIN-2060 Done) | per-account isolated `CLAUDE_CONFIG_DIR`; ProviderDefinition must **declare** the store model, not hard-code it (TIN-2078, prompt 41); fix the derivation self-contradiction where a default `~/.claude` account can resolve the WRONG keychain service (TIN-2104, prompt 42) |
| Browser session bleed | manual-paste Claude OAuth: second account in same browser never gets a code (verified live) | **incognito-first per-account ephemeral browser profile**, no secret in argv (`browser_launch.zig`, TIN-2071, prompt 40) |
| Mid-turn lock contention | mid-turn account swap can hang FOREVER on a sibling session's flock | **try-lock + re-elect** instead of blocking (TIN-2052, prompt 41; distinct from Done TIN-1816) |
| Silent lock waits | second same-account launch silently blocks with no output | bounded "waiting on `<account>` (`<reason>`)" notice + readiness that never mislabels a live session as stalled (TIN-2049, prompt 44) |

**Concurrency posture the prompts demand:** *concurrent isolated accounts* is the model. Independent providers proceed in parallel; independent accounts of one provider proceed in parallel; a given `provider:account` pair **serializes** (single-writer). Load can spread across accounts while each account's refresh is exclusive. The Claude analogue must be proven: TIN-2077 — 2 live Claude accounts concurrently, one mediated reauth, **zero disturbance** to the other session, committed `docs/evidence/claude-concurrent-handoff-<UTC>/`.

### 2.3 Refresh scheduling vs failover — what is and isn't claimed
- **Proactive per-account scheduled refresh**: yes — the warm scheduler refreshes each consenting account before its own expiry. This is per-account keepalive, not request load-balancing.
- **Election/failover is Phase-1 first-match**, NOT weighted routing or load-spreading (`AccountPool.elect`, account_pool.zig:195-203, first selectable && available non-excluded; `list` ignores filters). The prompts explicitly forbid claiming otherwise — sophistication is a *named gap*.
- **Never-halt routing ladder (prompt 41, both Urgent/In Review — not finished):**
  - Identity dedupe BEFORE any election/routing/refresh decision (`identity_graph.distinctLiveIdentities`, TIN-1822) — the max-2==max-1 trap: real incident where the same OpenAI account 38079d6acec6 (AAS-locked, openai/codex#25737) presented as two routes; GH **#338 P1 OPEN** (codex-max pool with zero selectable routes because max-1 ≡ max-4).
  - Cross-capability degradation: codex-max → codex-mini instead of halting (TIN-1811).
  - Quota-exhausted = **wait-and-continue** recoverable candidate that re-selects after quota reset, never marked dead (TIN-1812; fixes GH **#339 OPEN**: NoAccountSelectable halts despite a live cross-capability route).
  - Combined acceptance drill on the GF-RBE REAPI proof class, retiring the interim lab-wrapper cascade → `docs/evidence/never-halt-cross-cap-quota-drill-<UTC>/` (TIN-1813).
- **Resumability** (prompt 26): browser-launched auth flows must survive interrupted shells and child-process exits; scripted harness tests for cancel, timeout, callback, restart, provider denial; TIN-2045 tracks chooser-resume refused under isolated_persistent.
- **Reauth is the last resort AFTER proactive refresh fails** — and it is always mediated (see §3.3).

### 2.4 Keepalive daemon surfaces (prompt 39, gated on prompt 26's TIN-2047)
- **Read-only loopback status board** (TIN-1827): pure `ui_server.routeRequest` wired behind a `UiListener`, 127.0.0.1-only, exact-match `isLoopbackHost` (anti-DNS-rebind), structural redaction (AccountStatus structurally carries no token/account_id).
- **Production daemon socket** (TIN-1831): today `experimental_socket_stub`, `production_supported:false`, `hosts_stay_afloat:false` (daemon.zig:238-246); socket `refresh` returns "refresh unsupported". Upgrade to real control (status/refresh/reauth-trigger); flip the flags ONLY on evidence.
- **Every 127.0.0.1 listener** (39's board, 40's stepper, 31's socket, 44's JSON) is gated on the **per-session loopback auth token** — TIN-2047 / GH #376, owned by prompt 26, consumed by everyone else, never re-implemented.
- **Callback re-login composed into the warm loop** (TIN-1828): needs_reauth → mediated command-owned handoff (in-agent-reauth-handoff-contract-2026-05-14.md:16-21), no silent browser/device login; account **re-warms without process restart**. Depends on prompt 40's TIN-1805 adapter framework.

---

## 3. Multi-account model — intended architecture

### 3.1 Account types and identity
- Real topology to support (Jess's messy actual fleet): WORK Claude Team + PERSONAL Claude Pro + WORK Codex + PERSONAL Codex, **some sharing an underlying identity**; ≥5 distinct $200 codex-max accounts exist per house memory; muxing must support CONCURRENT distinct accounts.
- Two store models, both first-class:
  - **home-scoped-file** (Codex: `auth.json` in an isolated per-account home) — "data not Zig" holds here.
  - **os-keystore-singleton** (Claude/macOS: keychain service derived from `CLAUDE_CONFIG_DIR` hash) — needs compiled support; ProviderDefinition must *declare* keychain derivation, identity claims, and reauth browser isolation (TIN-2078), consistent with TIN-2060 ground truth (Done, never reopen).
- **Stable identity labeling**: `claude:<org>:<account>` derived from `oauthAccount.accountUuid` (NOT userID, NOT organizationUuid), hashed sha256_12hex like Codex; fail-safe `present=false/account_id_hash=null` on unusable input; structural redaction to hashes + masked email hint (src/identity/claude_identity.zig). Distinct-live-identity counting dedupes by IdentityKey **before** any routing/refresh decision (TIN-1822).
- **De-codexed core**: `src/provider.zig` per-provider branches (:18-56) → generic `provider_schema` calls (TIN-1818); polymorphic CLI dispatch `oauth-mux <provider> run` replacing hard-coded `.codex_adapter` at main.zig:62 (TIN-1819), riding prompt 26's typed seams (TIN-1789) — with **honest output**: Claude has no seamless harness adapter and the CLI must say so.

### 3.2 Enrollment (prompt 40)
- `oauth-mux init --interactive` is a **no-op today** (TIN-2063) → becomes a guided four-account (work/personal × Claude/Codex) cold-start flow with **no baked insider topology**, honoring account-enrollment-agent-contract-2026-05-01 (Visibility → Admission → Mutation):
  - Codex: scaffold isolated home + device-code login **handoff** (enrollment never runs `codex login` itself).
  - Claude: scaffold isolated `CLAUDE_CONFIG_DIR` + **incognito-first per-account browser launch** (TIN-2071: tier1_print / tier2_ephemeral_chrome, ephemeral profile create/delete, no-secret-in-argv — code proven, unwired) + hand off to vendor `claude /login`.
- Proof: scripted cold first-run e2e (`just first-run-e2e`) enrolling four accounts from nothing.

### 3.3 Mediated reauth (prompts 40 + 39 + 46)
Doctrine: **oauth-mux mediates, it does not run logins.** The mediator is `src/reauth/orchestrator.zig` (4 seams, NO login seam); the engine is `src/enroll/reauth.zig` — hardened but **imported only in a test{} block** (main.zig:20121-20126); production `runReauth`/`runEnroll` use repair_state handoffs + command-owned CLI login. The job across prompts is **wiring proven pure cores into production, not inventing**.
- Done substrate (build on, never redo): TIN-1806 (reauth CLI verbs + `OMUX_REAUTH_*` env), TIN-1807 (loopback PKCE callback server), TIN-2048 (887-line orchestrator commit), TIN-2064 (orchestrator-shape decision, #344 vs #378). PRs #422 (device_code flow-composition arm), #423/#424 (command-owned approval surface + handoff env/readiness) landed — **no provider flipped to engine-run**; approval still cannot invoke the engine.
- TIN-1804: **single-flight reauth queue** — in-proc mutex + on-disk flock + TTL reaper (reusing repair_state flock idiom :362); two racing reauths for one `provider:account` yield exactly one job + one reaped stale lock.
- TIN-1805: **ReauthAdapter vtable + registry**; the only composed flow today is Codex `device_code` (`flow_composition.runFlow`; redirect_loopback/command_owned/pat_paste → `error.FlowFailed`, :65-75). Claude stays vendor-CLI, contract-pinned; engine-run loopback would require the provider-boundary amendment that closed-unmerged PR #354 carried and which never landed.
- TIN-1808: 127.0.0.1 operator web UI (`web_ui.zig`) — health board + **live re-login stepper**, replacing the stub `/callback` returning literal "OK" (:505-528).
- Prompt 42's TIN-1821 matures the in-tree Claude reauth adapter (`src/enroll/claude_reauth.zig`, 394 lines, hardened via PR #409) to its honest ceiling: cassette-backed, PKCE dedup onto `oauth.generatePkce` (oauth.zig:123), materialized via the Claude vtable shape (TIN-1820 gates it), wired to a production command behind **explicit consent** — while default Claude login remains `claude /login`.
- Prompt 46's `omux_reauth_*` fronts ONLY the mediated command-owned trigger/handoff — an embedder receiving a reauth need gets a command-owned next-action (e.g., "run `claude /login`"), never a silent login performed on its behalf.

### 3.4 Provider adapters and the truth ledger (prompt 42 + 26)
Current honest ceiling, which every surface must reproduce exactly:
- **Codex/OpenAI**: ONLY `live_proven` (provider_schema.zig:683,710), backed by 4 evidence dirs (engineered-quota-handoff-20260509 — real 429 `usage_limit_reached` absorbed with same-turn retry to a credited account; managed-quota-handoff-20260508; live-e2e-clean-lineage-20260612; concurrent-accounts-live-20260612). Unproven even for Codex: same-thread continuity across account boundaries, mid-turn streaming recovery, bare-Codex daemon hot-swap.
- **Claude**: `auth-status` `local_live_proven` ONLY (proves no quota/tier/model call); NO harness adapter (synthetic smoke `just smoke-broker-claude` only); login vendor-CLI; **zero quota signal** (TIN-1824 empirical quota-reset test plan, GH #212, must run before any Claude-quota claim); proactive-refresh grant flipped + consent-gated but evidence-less.
- **Linear / Figma**: OAuth bearer BLOCKED (live 400/403); only PAT/api-key identity lanes `local_live_proven`.
- **Gemini**: capability-less stub (:873-891) — never listed as supported. **MCP**: resource-metadata `public_live_proven`; bearer resource blocked (405).
- Adapter maturation deliverables: keychain derivation fix (TIN-2104), expiry-unit verification for vercel/gemini epoch-ms + codex JWT-exp (`tokens.access_token`) + claude `.milliseconds` (TIN-2079 — mis-aging risk), **wire-cassette recorder/replayer** so real Codex wire behavior is recorded once and replayed offline in CI with no spend (TIN-1823, GH #176; cassette technique: neutralize-on-disk + reconstruct-in-memory per fixture_redaction), CredentialMaterializer Claude shape (TIN-1820; today only `chatgpt_auth_tokens`, methods.zig:508,520).
- IDE auth-seam adapters (TIN-1829, prompt 39): Bearer / proxy / credential-file / MCP seams driven by the declarative ProviderDefinition registry, per-capability proof status kept honest.
- **Broker invariant** underneath all of it: no raw token bytes cross the account-pool boundary (account_pool.zig:8); `account/select` currently returns placeholder handle `ch:<id>:<ts>` — freeze the honest surface.

### 3.5 Fleet dimension (prompt 45, runtime side — parked, see §6)
Tailnet route-state RPC so a fleet of daemons shares liveness ("multiple machines, one honest account picture", TIN-1835); degrade-to-local when the broker ("honey") is unreachable (TIN-1836); lab HM policy module `lab/nix/home-manager/oauth-mux.nix` with honey=broker vs client role selection, tailnet ACL tags, sops bindings by NAME only, never sops-materializing rotating tokens (TIN-1837 — the sops-nix codex auth-poisoning incident makes this last rule blood-earned).

---

## 4. Delivery / productionization bar — what "shipped" requires

### 4.1 Build substrate (universal gate, ownership = prompt 43)
Every prompt's step 1 is the same correction: **delete `WORKSPACE.bazel`** (WORKSPACE alongside MODULE.bazel is a house migration defect), Bazel 8 **Bzlmod-only**, registry order tinyland-inc/bazel-registry → BCR, **endpoint-free bazelrc** (endpoints are ENV authority: `BAZEL_REMOTE_CACHE`, `GF_BAZEL_SUBSTRATE_MODE`, `BAZEL_REMOTE_EXECUTOR`; `GF_BAZEL_REMOTE_UPLOAD=true` only trusted default-branch), CI as thin wrapper on `tinyland-inc/ci-templates/.github/workflows/spoke-ci.yml@v2.0.0` with `default_runner_class: tinyland-nix`, never a standalone runner. New recipes to ADD: `just endpoint-free-check` (grep-guard) and `just secrets-scan-dir` (gitleaks). Proof currency: **GF-RBE executor run ids** (cache-backed ≠ RBE; "never report cache-backed as RBE"). The proof-execution substrate itself is **TIN-2105** (In Review; PRs #420/#421 landed skeleton + dispatch, explicitly *started, not proven*): a bounded, countable, executor-backed Zig REAPI target class that prompts 39/41/46 (and 45 step 7) run their evidence on. All promoted tests EXTEND prompt 26's `src/tests.zig` root (TIN-1787) — never a second test tree. Open GF gaps bounding claims: TIN-2220 (JWT renewal — long runs 401 mid-build), TIN-2219 (off-cluster public ingress for token exchange). RustFS is the S3 substrate (MinIO/Garage are hallucinations). CI operational note from memory: cross-compile runs remotely with no concurrency group — drain PR fleets SEQUENTIALLY or jobs get CANCELLED.

### 4.2 Packaging SSOT (prompt 43)
- ONE hermetic Bazel-module packaging SSOT (TIN-2046) replacing hand-maintained lane config inline in `scripts/release-local.sh` (whose inline nfpm config currently beats static `dist/nfpm.yaml`).
- Derived lanes (TIN-2050): 6 CLI tarballs `oauth-mux-{x86_64,aarch64}-{linux,macos,windows}.tar.gz`, curl installer (`dist/install.sh`, SHA256SUMS-verifying), rpm + deb (nfpm), **binary-only** Homebrew tap (Jesssullivan/homebrew-omux — the tinyland-inc tap is a 404/hallucination; formula asserts `test ! -e bin/codex`, tap must NOT ship the shim; tarball/deb/rpm/curl DO ship it; windows tarballs binary-only), nix source flake, GitHub assets, plus **NET-NEW darwin `.pkg`** (pkgbuild). Version reconcile: everything to **0.1.13** (build.zig.zon + tag v0.1.13 are the SSOT; nix flake lags at 0.1.7-last-proof; published tap already 0.1.13 — only the local clone branch `codex/oauth-mux-0.1.11-checksums` is stale). **npm RETIRED** (registry stuck at 0.1.9; TIN-2042 Canceled — never revive); zero `.app`/`.dmg`/AppImage/`.desktop` claims ever (none exist).
- Cross-arch flake outputs for all 6 targets (TIN-1832); byte-reproducible builds — two independent builds, identical SHA256SUMS, zig pinned 0.14.1 (TIN-1833); greenfield HM service module `nix/modules/oauth-mux-service.nix` — binary-only default, `codexShim` opt-in, secrets by NAME only, never sops-materialize rotating tokens (TIN-1834).
- **Real launchd `.plist` + systemd `.service` units emitted FROM the SSOT** (TIN-1830) so the keepalive daemon installs/enables/disables as a first-class service, replacing the copy-paste templates in docs/stay-afloat-wrappers.md:270-323; install/enable/disable QA on BOTH macOS and linux.

### 4.3 SDK / FFI (prompt 46 — parked by ledger, see §6)
- Freeze stdio JSON-RPC as `surface_version:1` (SURFACE_VERSION=1 at broker/mod.zig:27): published JSON-schema per method; `credential/refresh`, `events/append`, `events/subscribe`, `policy/request_admission` honestly marked `not_implemented`; `oauth-mux mcp` published as the SDK; round-trip CI test (TIN-1798). Contract explicitly EXCLUDES `process/restart`, `session/respawn`, `auth/login_browser`, `provider/probe` (:329-345) — the FFI must not add them.
- Greenfield `src/ffi.zig` C-ABI: `omux_broker_open`/`omux_request`/`omux_string_free` over prompt 26's omux-core (TIN-1799); build.zig static+shared libs + generated `omux.h` + 6-target cross-compile matrix (TIN-1800); `omux_resume_*` over existing SessionId types + `omux_reauth_*` fronting the mediated trigger (TIN-1801); link test asserting no raw token crosses; one non-CLI (coye.ai-shaped) embedder fixture end-to-end through either door, `docs/evidence/omux-sdk-embedder-<UTC>/` (also satisfies prompt 26's "one non-CLI consumer exercises the typed seam" acceptance).

### 4.4 Observability / alerting / never-halt UX (prompt 44)
Load-bearing invariant: **no-spend everywhere** — every JSON surface, alert transition, and stats record is free_local/free_command, reading already-recorded state; live probes only behind `OMUX_LIVE_QA_CONFIRM=spend-real-calls`, never in default checks or daemon loops; broker Policy defaults `allow_interactive=false, allow_mutating=false, spend_admitted_for_session=false`.
- Bounded wait notice + honest readiness (TIN-2049); reauth job state/`reauth_in_progress` threaded from **repair_state** (production path — NOT the unwired orchestrator engine) into preflight/route/doctor JSON (TIN-1802); per-account route-state + resume-index health from `src/health.zig` into `accounts list`/`route explain` using qa-handoff-matrix vocabulary, never asserting a specific route currently selectable (TIN-1803); retention caps on status ndjson + smoke dirs with opt-in sessions sweep (TIN-2044); de-flaked stay-afloat-observe e2e deterministically reporting `target_failed` — diagnostic only, `relaunch_admitted=false` hardcoded (TIN-2103); **push-notification alert channel** for reauth-needed (repair_state `appendEvent`) and keepalive-failure (warm_scheduler TickReport/RefreshResult) transitions — fires off already-recorded state, transport credential by name only, NOT coupled to the experimental daemon socket (TIN-2061); identity-keyed per-account usage-stats export to a coye.ai/FinanceBro **fixture** — Codex quota rich (broker `quota/observe`/`quota/status`), Claude quota honestly absent, never fabricated (TIN-2062).
- **Shared loopback-UI contract across 39/40/44 — one operator surface, not three**: structural redaction, exact-match `isLoopbackHost`, CSRF Origin gate on POST, row-index selector so raw account_id never reaches the DOM, all gated on the TIN-2047 token. Seam split: 39 = read-only keepalive liveness board; 40 = interactive re-login stepper + health board; 44 = no-spend JSON + push alerts + stats feed.

### 4.5 Site / docs truth (prompt 45, site half; separate initiative "Presence And Narrative", TIN-734 In Progress)
The site (tinyland-inc/omux.xoxd.ai, static SvelteKit/GH-Pages) is a **passive truth consumer, never runtime authority**. Deliverables: version truth-sync 0.1.7→0.1.13 across six copy surfaces + bootstrap spec, with a CI version-parity check that fails on drift; provider-matrix reconciliation via `just regen-providers` mapping the runtime 4-value per-capability `proof_status` onto the site's 3-value enum so **nothing weaker than live_proven ever renders live** (Codex stays the only live-proven; fix README Bedrock/Azure phantom "Planned" rows and the 7-vs-10 summary; keep NotClaimed boundaries — no same-thread continuity, no mid-turn streaming recovery claims); add missing `static/og-image.png` and resolve the 404ing `install.sh` curl reference; document the REAL deploy lane (GH-Pages deploy-pages@v5 + Cloudflare DNS-only gray-cloud, a noted divergence from the house CF-Pages assumption) with a post-deploy gstack `/canary` health-gate; federation described as **PLANNED** only — `static/pulse/` placeholder carrying contract shape, no live ingest, "signed static snapshots are NOT federation" (TIN-731 design Done; real federation = TIN-975, elsewhere). Docs debt on the runtime side: reconcile the three stale 2026-06-13 decision docs + `docs/runbooks/reauth-accounts-2026-06-01.md` against HEAD; update tracing/qa-handoff/dogfood/release-install-lanes/adoption/home-manager docs; append implementation-update logs to the enrollment and reauth-handoff contracts.

### 4.6 Universal evidence discipline
Every claim hedged with literal status words; every acceptance clause backed by a **dated `docs/evidence/**` dir with summarizer verdict, printing no token/account-id/path**; five-lane research packet (repo-truth, Linear-parity, history/JSONL, sibling/authority, web/primary-source — RFC 9700, 8628, 8252, 7636, OAuth 2.1) + claims ledger (`claim | source | proof status | next proof`) with a mandatory Bazel-8-Bzlmod+GF-RBE posture row **before editing** in every prompt; web findings land as repo-owned tests/docs, never prose. Verify every file:line citation against HEAD before asserting (line numbers drift). Linear updates with proof links; never invent TIN ids; never revive Done/Canceled TINs (1791→dup of 1826; 2058/2073/2074/2087, 1806/1807/2048/2064, 1816, 1817/2060/2070/2054, 2038 Done; 2042 Canceled; 2113 in-code no-row; TIN-1852's state must not be claimed).

---

## 5. Dependency / sequencing graph

### 5.1 Structural roles
- **Prompt 26 = foundation root.** Owns: CredentialLock (1785), single-writer flip (1786), test root (1787), typed-seam split (1788/1789), omux-core + shape-tagged materializer + broker mutex (1790), refresh serialization completion (1792/1793/2059), resume arch (2045), loopback token (2047), proxy perf (2040), age bech32 (2051), provider proof ledger, boundary/repo-contract repair, v0.1.13 release proof. Everything else consumes these and is forbidden to re-own them.
- **Prompt 43 = substrate + delivery steward.** Owns the WORKSPACE.bazel deletion + Bzlmod migration (the gate every other prompt merely *asserts*), TIN-2105 REAPI proof class (the substrate 39's soak, 41's drill, 46's freeze, and 45's seam tests all execute on), packaging SSOT and all install lanes, service units (1830) consumed by 39's daemon story.
- **Prompt 40 → 39 coupling:** 39's TIN-1828 (callback re-login in the warm loop) explicitly depends on 40's TIN-1805 (ReauthAdapter framework). 40 in turn builds on Done reauth substrate + 26's token/seams.
- **Prompt 41** consumes 26 (1785/1786/1789) + 43 (proof class); its routing truth is *surfaced* by 44 (44 owns UX/JSON, 41 owns logic).
- **Prompt 42** consumes 26 (materializer/broker mutex); internal gate TIN-1820 → TIN-1821; its refreshed truth matrix **feeds prompt 45's** site regen.
- **Prompt 44** consumes 26 + references 39/40/41/42/43; strictly the surfacing/alerting half.
- **Prompt 45**: site half consumes 42's matrix (can start earlier for version/assets/deploy items); runtime federation seam (step 7) hard-depends on 43/TIN-2105 and must NOT run off GF-RBE against the WORKSPACE-defect repo.
- **Prompt 46** binds over 26's core split, inherits 39's TIN-1826 for eventual `omux_refresh`, fronts 40's mediator, proves on 43's class — structurally last.

### 5.2 Order of operations
```
GATE (once, owned by 43): WORKSPACE.bazel removal → Bzlmod-only → endpoint-free →
                          ci-templates@v2.0.0 latch → TIN-2105 executor-backed proof class
        │
26 foundation (locks 1785/1786 · serialization 2059/1792/1793 · seams 1788/1789/1790 ·
               token 2047 · resume/2045 · ledger)          ── largely landed per memory;
        │                                                     remaining: 1785 write-path lock,
        ├────────────┬───────────────┬──────────────┐        2059 fixture, 1792/1793 closeout
        ▼            ▼               ▼              ▼
   39 keepalive   41 never-halt   42 adapters    44 observability     (parallelizable band)
   (1826→1825→    (1818→2078→     (2104,2079,    (2049,1802,1803,
    1827→1828*→    1819; 1822;     1823; 1820→    2044,2103,2061,
    1829→1831→     1811/1812→      1821; 1824;    2062)
    2057 SOAK)     1813; 2052;     matrix)
        ▲           2077)              │
        │ *1828 needs                  ▼
   40 reauth lane (1804→1805→2071→2063→1808)      45-site (TIN-734: version sync,
   [LEDGER: queued behind evidence chain]          matrix regen ← 42, assets, deploy+canary,
        │                                          planned-federation narrative)
        ▼
   46 SDK/FFI (1798→1799→1800→1801→embedder)   [LEDGER: PARKED]
   45-runtime federation seam (1835→1836→1837) [LEDGER: PARKED]
   43 federation-packaging nix TINs (1832/1833/1834) [likely PARKED — see §6.2]
```
- **Must land first:** the build gate (43) and prompt 26's remaining lock/serialization items — nothing evidence-grade is trustworthy before per-account refresh is race-safe and the proof substrate is executor-backed.
- **Parallel band:** 39 (minus 1828), 41, 42, 44, 45-site are mutually independent given 26+43, coordinated only by the shared loopback-UI contract (39/40/44) and the one-test-root rule.
- **Terminal:** 2057 golden soak (needs 1825/1826/1827 + reauth-handoff protection), 1813 drill, 2077 Claude gate — the three flagship evidence dirs. Then the parked tail (46, federation) if/when unparked.

---

## 6. Tensions, contradictions, staleness (drafts vs ledger vs HEAD)

1. **LEDGER ITEM 12 OVERRIDES THE CORPUS' OWN SEQUENCING.** "omux: Level-3 evidence leads July. TIN-1517 → TIN-950 → TIN-951 (gates TIN-916). Reauth lane (TIN-1805–1808) queues behind; ffi-sdk + federation-packaging formally parked." Consequences: prompt 46 is parked in its entirety; prompt 45's runtime seam (1835/1836/1837) is parked; prompt 40's core TINs (1804/1805/1808 — the reauth lane) queue behind the evidence chain. Any prompt/plan/Linear framing to the contrary gets a **dated correction note citing item 12** — never a silent rewrite.
2. **The ledger's evidence-chain TINs (1517/950/951/916) appear NOWHERE in the corpus.** The prompts' evidence spine is TIN-2057 (soak) / TIN-1813 (drill) / TIN-2077 (Claude gate). The planner's first job is resolving this mapping in Linear before dispatching — do not assume 2057 ≡ the ledger chain.
3. **Circular squeeze on the golden soak:** TIN-2057 requires "reauth-handoff protection," and 39's TIN-1828 depends on 40's TIN-1805 — but the reauth lane is queued behind the evidence chain the soak leads. Resolution options for the planner: run the soak with proactive refresh only + repair_state handoff (the production path 44 threads from), scope TIN-1805 minimally as a soak dependency, or accept a bounded soak that documents reauth as out-of-window. Must be decided explicitly, not drifted into.
4. **Prompt 43 straddles the park line.** Its release-packaging TINs (2046/2050/2105) and TIN-1830 are live (2105 is load-bearing for everything), but 1832/1833/1834 sit in the **federation-packaging** Linear project the ledger formally parks. Treat the nix-fleet trio as parked-pending-clarification; do not let "packaging SSOT" smuggle them in.
5. **WORKSPACE.bazel removal is claimed as step-1 by all nine prompts but owned by 43/TIN-2105.** Executed naively as parallel workflows, eight prompts race one deletion. The planner must make it a single shared gate with one owner and have every other workflow *verify*, not perform, it. Same dedup applies to adding `just endpoint-free-check` and `just secrets-scan-dir` (each prompt says "add").
6. **Stale-doc landmine (every prompt flags it):** dual-writer-refresh-designation-2026-06-13.md, refresh-authority-adr-trace-2026-06-13.md, provider-repair-contracts.md still say "grant flip BLOCKED" — pre-dating #417/#418. Never cite them in either direction; reconciliation is a deliverable (39, with 26 also naming it). Likewise `docs/runbooks/reauth-accounts-2026-06-01.md`.
7. **Merged ≠ proven, systematically:** keepalive wired but evidence-less; TIN-1825 core wired but ticket OPEN; reauth engine hardened but test-only; #420/#421 REAPI "started, not proven"; justfile:260 says Bazel recipes "not proof authority yet". House memory adds the sharpest version: unit-green ≠ working (the 3-week codex temp-home poisoning shipped green). Every workflow must treat code-comment claims like provider_schema.zig:797-798 as unproven.
8. **"To the masses" vs house posture:** omux has no golden-objective entry, no ecosystem-map row, is not in the initial agent-PR auto-merge allowlist, and the ledger parks its most product-shaped arcs. House AI-product doctrine (paid pilots / protected previews, never public self-serve) plus heavy Codex TOS mean the vision statement must stay operator-tool-shaped for now. The stray omux CNAMEs (glorious.build — deleted in PR #13; cmus placeholder — still omux-branded with `static/CNAME=omux.xoxd.ai`) are hygiene owed to the brand.
9. **Version-drift traps with exact polarity:** runtime 0.1.13 (build.zig.zon + tag) is the SSOT; published tap already 0.1.13 (do NOT claim it lags — only the local `codex/oauth-mux-0.1.11-checksums` branch is stale); nix flake genuinely lags at 0.1.7; site copy at 0.1.7 (+0.1.6 in the bootstrap spec); Linear pins no version; site package.json 0.0.1 is a distinct field — don't touch. Broker BUILD_TAG "oauth-mux 0.2.0+broker" is yet another distinct string (46).
10. **Election honesty tension:** the golden story implies smart failover, but `AccountPool.elect` is first-match Phase-1 and no prompt is chartered to build weighted routing — 41 builds dedupe + degradation + wait-and-continue only. Marketing/docs must not outrun this.
11. **Prompt 44 vs 39 socket timing:** 44's alert channel must not depend on the daemon socket while 39's TIN-1831 productionizes it — fine if 44 stays journal/scheduler-sourced, but a naive integration inverts the constraint.
12. **Claude concurrency claims:** prompts repeatedly warn against overstatement — Claude is auth-status `local_live_proven` only, no adapter, no quota signal, no evidence for proactive refresh, TIN-2077 unproven. Memory confirms the manual-paste session-bleed defect live (TIN-2060/TIN-2077 lineage). Any workflow output implying "Claude keepalive works" before the soak + 2077 evidence dirs commit is a truth-posture violation.
13. **Muxxing safety history (memory, not in corpus):** temp-CODEX_HOME muxxing corrupted `~/.codex` for 3 weeks; decoupled to opt-in (bde09d72); TIN-1851 Model B guards (home-is-store, canonical-overlap refuse, config-fresh+scrub, auth shadow backup) are the non-negotiable guard set. Planner should ensure no workflow re-enables the old adapter path outside those guards.
14. **Minor ownership frictions to police at dispatch:** 26's scope list names "keepalive" though 39 owns it; TIN-2059 named by both 26 (owner) and 39 (consumer); TIN-2045/2047 coveted by several prompts but 26-owned; TIN-2113 has no Linear row (don't create/re-implement); TIN-1830 is 43's though 39's daemon story reads like it wants it.

---

## 7. Master deliverable checklist (every discrete deliverable, tagged by prompt)

**Shared gate (execute ONCE, owner P43; all others verify)**
- [ ] (43) Delete `WORKSPACE.bazel`; Bzlmod-only; registry order tinyland-registry→BCR — **[gate for 26,39–46,45§7]**
- [ ] (43) Endpoint-free `.bazelrc`/`.bazelrc.flywheel` + ADD `just endpoint-free-check` grep-guard
- [ ] (all) ADD `just secrets-scan-dir` (gitleaks, tinyland rules) — dedupe to one landing
- [ ] (43) CI latched to ci-templates spoke-ci.yml@v2.0.0, `default_runner_class: tinyland-nix`
- [ ] (43) TIN-2105: bounded Zig REAPI class promoted to countable **executor-backed** GF-RBE runs (respect TIN-2219/2220); dated evidence dir + run id
- [ ] (each prompt) Five-lane research packet + claims ledger w/ Bazel/GF-RBE posture row, landed pre-edit: `docs/research/omux-foundation-…`(26), `…multi-account-never-halt-…`(41), `…delivery-ssot-…`(43), `…observability-neverhalt-…`(44), plus 39/40/42/45/46 packets

**Prompt 26 — broker foundation**
- [ ] Exploration packet `docs/research/omux-foundation-<UTC>.md`
- [ ] Boundary repair: AGENTS.md/README ownership maps (runtime vs site vs tap vs release notes vs secrets); `tinyland.repo.json` conformance
- [ ] TIN-1785: per-`provider:account` blocking flock on refresh write path (`refreshCodexAccountAuthFile`), factored from `acquireRepairLockBlocking`; concurrency tests that FAIL against the old no-lock path
- [ ] TIN-1786: `shouldPreserveChildAuth` → broker-owned-only
- [ ] TIN-2059: dual-writer refresh under RT rotation; fixture proving stale result can NEVER overwrite newer token; crash/retry tests
- [ ] TIN-1792: surface flags + concurrent-path smoke; TIN-1793: freeze + incident closeout doc (GH #336/PR #337)
- [ ] Resumable browser-auth: harness tests for cancel/timeout/callback/restart/provider-denial; TIN-2045 chooser resume under isolated_persistent
- [ ] TIN-1788/1789/1790: main.zig + provider module split behind typed seams; omux-core extraction; ≥1 non-CLI consumer/fixture over the seam
- [ ] TIN-1787: `src/tests.zig` single test root
- [ ] TIN-2047: per-session loopback auth token on EVERY 127.0.0.1 listener (GH #376)
- [ ] TIN-2040 proxy perf/correctness; TIN-2051 age bech32 decode
- [ ] Provider truth ledger keyed to `proof_status`, proof link per provider; site reconciled via `just regen-providers`
- [ ] v0.1.13 release-lane proof: dry-run install + broker smoke under GF validation
- [ ] Linear proof-links: 1785, 1786, 1792/1793, 2059, 2047, 2040, 2051, 2045

**Prompt 39 — keepalive golden-metric daemon**
- [ ] TIN-1826: broker-owned serialized `credential/refresh` (retire not_implemented @ methods.zig:49; flip surface/info flag; warm loop + reauth + FFI inherit ONE path; `just smoke-broker` over serialized concurrent path)
- [ ] TIN-1825: warm-scheduler property tests (saturating `refreshDueAtMs`, max_failures backoff, never-halt skip, degenerate-success guard) + anti-naive-scheduler fixture
- [ ] TIN-1827: wire UiListener into daemon — loopback-only, exact-match host, TIN-2047-gated, structural redaction; `just daemon-loop-host` smoke
- [ ] TIN-1828: callback re-login composed into warm loop; expiry → handoff-emitted → re-warm WITHOUT restart (scripted proof) *(depends 40/TIN-1805 — see §6.3)*
- [ ] TIN-1829: IDE auth-seam adapters (Bearer/proxy/credential-file/MCP) from ProviderDefinition registry; per-seam unit tests + cassette replay
- [ ] TIN-1831: production socket transport (status/refresh/reauth-trigger); flip `production_supported`/`hosts_stay_afloat` ONLY on evidence; daemon-status JSON contract test
- [ ] **TIN-2057 GOLDEN: committed `docs/evidence/keepalive-golden-soak-<UTC>/`** — 2×Claude+2×Codex afloat, passing verdict, zero tokens/ids/paths
- [ ] Reconcile 3 stale 2026-06-13 docs + reauth-accounts runbook + daemon-boundary doc
- [ ] Linear proof-links: 1826/1825/1827/1828/1829/1831/2057; do NOT re-implement TIN-2113

**Prompt 40 — enroll + mediated reauth** *(ledger: queued behind evidence chain)*
- [ ] TIN-1804: single-flight ReauthJob (in-proc mutex + flock + TTL reaper); two racing reauths → exactly one job + one reaped stale lock
- [ ] TIN-1805: ReauthAdapter vtable + registry + Codex device_code arm; cassette replay driving a mediated handoff
- [ ] TIN-2071: wire browser_launch incognito-first per-account launch; account-2 distinct ephemeral profile, no bleed, no secret in argv
- [ ] TIN-2063: real `init --interactive` 4-account guided enrollment; `just first-run-e2e` cold proof
- [ ] TIN-1808: operator web UI (health board + live re-login stepper; real `/callback`; token-gated; CSRF; composed with 39's board as one surface); UI smoke
- [ ] Implementation-update logs appended to enrollment + reauth-handoff contracts
- [ ] Linear: 2071/1804/1805/1808 + 2063 proof-links; 1806/1807/2048/2064 noted Done

**Prompt 41 — multi-account types / never-halt**
- [ ] TIN-1818: de-codexed provider.zig; round-trip tests: codex auth.json AND Claude keychain through ONE path
- [ ] TIN-2078: ProviderDefinition DECLARES os-keystore-singleton (keychain derivation, identity claims, reauth browser isolation); schema test vs TIN-2060 truth
- [ ] TIN-1819: `oauth-mux <provider> run` polymorphic dispatch; honest no-Claude-seamless usage output
- [ ] TIN-1822: identity labeler maturation + `distinctLiveIdentities` before election; golden sha256_12hex test + max-2==max-1 regression fixture (GH #338)
- [ ] TIN-1811: codex-max→codex-mini degradation; route-state matrix test
- [ ] TIN-1812: quota-exhausted = wait-and-continue, re-selects after reset (GH #339)
- [ ] TIN-1813: `docs/evidence/never-halt-cross-cap-quota-drill-<UTC>/` on REAPI class; retire lab-wrapper cascade
- [ ] TIN-2052: try-lock + re-elect mid-turn; held-sibling-flock concurrency test
- [ ] TIN-2077: `docs/evidence/claude-concurrent-handoff-<UTC>/` — 2 live Claude, one mediated reauth, zero disturbance
- [ ] Update auth-state-models spec + qa-handoff route-state vocabulary; Linear proof-links on all 9

**Prompt 42 — provider-adapter maturation**
- [ ] TIN-2104: keychain-service derivation fix (default dir = base service, suffixed = derived); unit tests vs TIN-2060 shape
- [ ] TIN-2079: expiry-unit verification vercel/gemini + assert codex JWT-exp & claude `.milliseconds`; per-provider mis-aging tests
- [ ] TIN-1823: cassette recorder/replayer (GH #176); `just smoke-codex-cassette-replay`
- [ ] TIN-1820: Claude CredentialMaterializer shape; no-raw-token-bytes boundary test *(gates 1821)*
- [ ] TIN-1821: mature + wire Claude reauth adapter (cassette-backed, PKCE dedup onto oauth.generatePkce, consent-gated production command); docs assertion "Claude login = command-owned"; do NOT revive PR #354
- [ ] TIN-1824: dated Claude quota-reset test plan + recorded observations (GH #212)
- [ ] Truth-matrix refresh keyed to proof_status; `just providers` diff → feeds P45
- [ ] Update future-adapter-roadmap, provider-proof-* docs, "Do Not Claim" list; Linear proof-links; Done deps terminal

**Prompt 43 — delivery/packaging SSOT**
- [ ] TIN-2046: hermetic Bazel-module packaging SSOT replacing scripts/release-local.sh inline config; dry-run deriving each lane
- [ ] TIN-2050: all lanes from SSOT + NET-NEW darwin `.pkg` (pkgbuild, install QA); `just registry-dry-run` (plan,npm,github,homebrew,system; `OMUX_REGISTRY_DRY_RUN_CONFIRM` gate); all lanes 0.1.13 incl. nix flake 0.1.7→0.1.13; npm stays retired
- [ ] TIN-1832: 6-target cross-arch flake outputs; `just home-manager-smoke` + per-arch builds *(park-check §6.4)*
- [ ] TIN-1833: byte-reproducible — two independent builds, identical SHA256SUMS, zig 0.14.1 pinned *(park-check)*
- [ ] TIN-1834: HM service module (binary-only default, codexShim opt-in, name-only secrets, never sops-materialize rotating tokens) *(park-check)*
- [ ] TIN-1830: launchd .plist + systemd .service emitted FROM SSOT; install/enable/disable QA on macOS AND linux
- [ ] Docs: release-install-lanes / adoption / home-manager; purge live-npm & .app claims; Linear proof-links; 2038 Done / 2042 Canceled recorded terminal

**Prompt 44 — observability / alerting / never-halt UX**
- [ ] TIN-2049: bounded wait notice + readiness fix; e2e proof
- [ ] TIN-1802: reauth job state → doctor/route/preflight JSON (from repair_state, NOT unwired engine); zero-spend contract test
- [ ] TIN-1803: route-state + resume-index health → accounts list / route explain; no-spend contract test; never assert route selectable
- [ ] TIN-2044: retention caps (ndjson + smoke) + opt-in sessions sweep; retention test; dogfood doc updated
- [ ] TIN-2103: deterministic `target_failed` e2e over N runs; diagnostic-only, restart inadmissible
- [ ] TIN-2061: push-alert channel (reauth-needed + keepalive-failure), fixture-fired proof, credential by name, socket-independent
- [ ] TIN-2062: identity-keyed usage-stats export consumed by in-repo coye.ai fixture; Codex rich / Claude honestly absent
- [ ] docs/tracing.md (OMUX_TRACE schema) + qa-handoff-matrix + dogfood docs; Linear proof-links both projects

**Prompt 45 — site truth (+ parked federation)**
- [ ] TIN-734: version truth-sync to 0.1.13 across 6 copy surfaces + bootstrap spec; CI version-parity check failing on drift
- [ ] TIN-734: provider-matrix regen (`just regen-providers` from ../oauth-mux ← P42 matrix); Codex-only-live test; no-blocked-rendered-live test; README Bedrock/Azure + 7-vs-10 fixes; keep NotClaimed
- [ ] TIN-734: og-image.png + install.sh resolution; no-404 checks
- [ ] TIN-734: deploy-lane truth docs (GH-Pages + CF DNS-only divergence note); gstack `/canary` post-deploy health-gate; `just boundary-check` verified/added; spoke CF-cred-free; no dynamic-adapter flip (TIN-1437 out of scope)
- [ ] Planned-federation docs section + `static/pulse/` contract-shape placeholder (no live ingest; TIN-731 Done, TIN-975 not claimed)
- [ ] Site gate: Bzlmod-only confirm, GF-RBE candidates latched endpoint-free, tinyvectors pin reconciled (0.3.0 vs 0.2.5)
- [ ] **[PARKED]** TIN-1835 tailnet route-state RPC; TIN-1836 degrade-to-local test; TIN-1837 lab HM federation module — each with GF-RBE run id on the P43 class when unparked

**Prompt 46 — embeddable SDK/FFI** *(ledger: PARKED — retain for later)*
- [ ] TIN-1798: freeze surface_version:1; JSON-schema per method; 4 not_implemented honestly marked; `oauth-mux mcp` published as SDK; round-trip CI test; broker-contract SDK note
- [ ] TIN-1799: src/ffi.zig C-ABI (open/request/string_free) over omux-core; C link test, no raw token crosses
- [ ] TIN-1800: static+shared libomux + generated omux.h + 6-target cross-compile matrix, GF-RBE-validated
- [ ] TIN-1801: omux_resume_* + omux_reauth_* (mediated command-owned only); FFI resume + handoff test, no silent login
- [ ] Embedder proof: non-CLI coye.ai-shaped fixture through either door; `docs/evidence/omux-sdk-embedder-<UTC>/`

**Corpus-wide hygiene**
- [ ] Dated correction notes (citing ledger item 12) on any prompt/Linear framing sequencing reauth/ffi-sdk/federation ahead of the evidence chain
- [ ] Resolve the ledger-chain ↔ corpus TIN mapping (1517/950/951/916 vs 2057/1813/2077) in Linear before dispatch
- [ ] Single-owner the shared gate work (WORKSPACE deletion, endpoint-free-check, secrets-scan-dir) across workflows
- [ ] Scrub stray omux branding/CNAMEs (cmus placeholder; glorious.build done) and the dangling `omux-website-bootstrap-2026-04-29.md` ref in site.scaffold
- [ ] Sequential CI drainage for multi-PR pushes (remote cross-compile has no concurrency group; parallel PRs get CANCELLED)

**The bar, in one line:** done = the broker provably survives refresh races and interrupted flows; keepalive keeps 2×Claude+2×Codex afloat in a committed soak; four messy accounts route deduped-degraded-never-hung; every provider claim matches its evidence; every install lane derives from one SSOT at 0.1.13; every proof ran executor-backed on GF-RBE with WORKSPACE.bazel gone — and nothing anywhere says unlimited, bypass, or pooling.
