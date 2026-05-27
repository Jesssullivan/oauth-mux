# oauth-mux Operational Hardening Plan
Date: 2026-05-20
Status: active plan and testable todo list; subordinate to `AGENTS.md`,
`docs/spec/broker-mcp-contract-2026-05-03.md`,
`docs/spec/codex-adapter-contract-2026-05-03.md`, and
`docs/spec/harness-session-authority-bridge-2026-05-05.md`.

## Purpose

Turn the May 20 BrokenPipe / Codex operations review into completion-metric
workstreams. The product anchor remains managed harness continuity:
`oauth-mux codex` must keep the active managed Codex session usable when auth,
quota, tier, or local runtime state changes. Restart, supervised relaunch, and
prepared fallback remain diagnostic infrastructure, not the success claim.

## Current Verified State

- Local upstream `main` is at `7a06632`, after PR #299 promoted a scrubbed
  current-release auth-failure wire fixture and local-path redaction gate.
  PR #289 fixed the Codex 0.132 SQLite resume authority regression, PR #290
  added the #176 `--require-proxy-meta` capture gate, PR #291 cut the
  `0.1.11` release, and PR #296 cut the `0.1.12` release for resume-picker
  namespace parity.
- GitHub read-only refresh at 2026-05-26: no open PRs; open issues remain
  `#67`, `#68`, `#163`, `#176`, and `#212`.
- Linear: `TIN-1624` is Done for the resume authority fix. `TIN-1591`,
  `TIN-738`, `TIN-937`, `TIN-736`, `TIN-893`, and `TIN-895` remain In
  Progress. `TIN-938` is Todo, `TIN-1079` is Backlog, and `TIN-950` is still
  marked Done even though GitHub `#176` remains open for real cassette
  acceptance.
- Release truth: public GitHub Release `v0.1.12` is published, not
  draft/prerelease, with installer, Homebrew, tarball, deb/rpm, npm tarball,
  handoff, and checksum assets. The public Homebrew tap reports stable/linked
  keg `0.1.12`. `npm view oauth-mux version` still reports `0.1.9`;
  `oauth-mux@0.1.12` is not published to npm.
- Current install truth: `/Users/jess/.local/bin/oauth-mux` is PATH-first and
  reports `0.1.12` with build id `v0.1.12`; `/opt/homebrew/bin/oauth-mux` also
  reports `0.1.12`. Native Codex resolves outside oauth-mux.
- Current no-spend route truth: `oauth-mux codex preflight --profile codex-max
  --capability codex-max --json` reports `ok:true`, `session_start_ready:true`,
  `fallback_ready:true`, `selectable_fallback_routes:2`,
  `single_route_at_risk:false`, `spends_provider_calls:false`, and
  `mutates_route_health:false`.
- Current process/fd truth for TIN-1591 remains containment, not resolution:
  the fresh 2026-05-26 snapshot shows soft fd limit `256`, max visible fd use
  at 73.4% of that limit, active Codex/oauth-mux processes, and orphan-listener
  candidates. One-snapshot helper fanout is not leak proof. Do not use dogfood
  probes for broad live reliability claims until repeated clean-baseline
  snapshots support that claim.

## Workstream 1 - BrokenPipe And Network-Blip Reliability

Priority: P0 now. Keep this as the next small PR.

Completion metric:

- Downstream Codex/client socket closes are classified as `client_disconnected`,
  not as provider degradation.
- Downstream close emits a redacted `proxy_client_disconnected` trace/status
  event and does not write degraded route health.
- Upstream/provider interruption is classified separately as
  `upstream_interrupted`, records provider-degraded evidence, and does not
  retry a same-turn request after a partial `200` stream has reached Codex.
- Upstream short-body EOF with `Content-Length` mismatch is treated as
  provider interruption, not successful route health.
- Benign close errors such as `BrokenPipe` / `ConnectionResetByPeer` do not
  bubble up as noisy `proxy: serveOne: BrokenPipe` operator failures.
- The regression is locked by a CI-safe smoke that reproduces client-close and
  upstream-interrupted paths without provider traffic.

Test commands:

```bash
python3 -m py_compile scripts/test-stub-codex.py scripts/test-stub-upstream.py
bash -n scripts/smoke-codex-provider-degraded.sh
just smoke-codex-provider-degraded-local
just test
just check-local
git diff --check
```

Todo:

- [x] Split streamed proxy outcome into client-disconnect versus upstream
  interruption paths.
- [x] Add no-spend stub coverage for downstream disconnects and provider
  degraded upstream interruption.
- [x] Add a CI-safe smoke for partial upstream `200` interruption that proves
  no same-turn retry after partial delivery and records provider-degraded route
  health.
- [x] Suppress benign proxy thread close noise while preserving real upstream
  diagnostics.
- [x] Land the WIP as a small focused PR before starting live cassette or
  provider-spend work. Landed as PR #279.
- [x] Publish or install a build that contains PR #279 before treating new
  installed `oauth-mux codex resume` dogfood as fixed. Completed for GitHub
  Release, user-local, and Homebrew as `0.1.11`; the fix remains included in
  current release `0.1.12`.

## Workstream 2 - No-Spend Route And Process Truth Refresh

Priority: P0 before any live Codex spend, cassette capture, or tracker claim.

Completion metric:

- The exact `oauth-mux` and `codex` binaries under test are recorded.
- Route election, fallback readiness, daemon state, status artifact verdict,
  and shell/PATH provenance agree or explicitly document disagreement.
- The refresh does not read token files, mutate credential stores, run upstream
  login, or spend provider calls.
- Any process-fanout concern is backed by fresh redacted snapshot output, not
  by stale memory/process impressions.

No-spend command set:

```bash
which -a oauth-mux
which -a codex
oauth-mux version --json
oauth-mux doctor runtime --profile codex-max --capability codex-max --json
oauth-mux accounts list --provider codex --json
oauth-mux route explain --profile codex-max --capability codex-max --json
oauth-mux codex preflight --profile codex-max --capability codex-max --json
oauth-mux codex broker-session-plan --profile codex-max --capability codex-max --json
oauth-mux codex status-latest --json
oauth-mux daemon status --json
python3 scripts/dogfood-process-snapshot.py
```

Todo:

- [x] Run the no-spend command set immediately after Workstream 1 is landed or
  intentionally before any live run.
- [x] Preserve a redacted summary under `docs/evidence/` only if it adds new
  proof value; otherwise keep it as operator scratch.
- [x] Block cassette/live work while the 2026-05-20 17:01 UTC snapshot showed
  `single_route_at_risk:true`.
- [x] Re-run no-spend route truth after spend-confirmed route-health repair.
- [ ] Re-run route truth immediately before cassette capture and verify
  `single_route_at_risk:false` still holds.

2026-05-20 17:01 UTC no-spend refresh:

- Active installed binary is public Homebrew `oauth-mux 0.1.9`; native Codex
  resolves outside oauth-mux and is not an oauth-mux shim.
- Runtime doctor is clean for the four named `codex-max` route stores.
- `codex:max-3#codex-max` is selected and selectable.
- `codex:max-1`, `codex:max-2`, and `codex:max-4` are runtime/broker ready but
  blocked as `unrecorded`; each needs an explicit spend-provider probe before
  it can be used as fallback evidence.
- `session_start_ready:true`, `fallback_ready:false`,
  `single_route_at_risk:true`.
- `codex status-latest` reports `brokered_without_fallback` from a rolling
  local artifact, with 160 `200` proxy turns and no quota handoff.
- `daemon status` is `not_running`; its stay-afloat snapshot is stale and must
  not override current preflight/route-explain truth.
- Process fanout snapshot is observational only: 8 agent trees, 6 oauth-mux
  processes, 13 Codex processes, 5 accumulated sessions, 6 duplicate helper
  groups, 4 orphan listener candidates, and no heap leak proven from a single
  snapshot.
Historical gate from this snapshot: do not start real cassette or
spend-confirmed live work until spare fallback capacity is restored or the
operator intentionally accepts a single-route-at-risk run.

2026-05-21 02:57 UTC post-repair no-spend refresh:

- Active binary is user-local `oauth-mux 0.1.9` at
  `/Users/jess/.local/bin/oauth-mux`; Homebrew `0.1.9` remains installed as a
  second candidate. Native Codex still resolves outside oauth-mux and is not an
  oauth-mux shim.
- Runtime doctor remains clean for the four named `codex-max` route stores.
- `codex:max-3#codex-max` is selected and selectable.
- `codex:max-4#codex-max` is now a live selectable fallback.
- `codex:max-1#codex-max` and `codex:max-2#codex-max` remain runtime/broker
  ready but blocked as `unrecorded`; they still need explicit spend-provider
  probes before being counted as additional fallback evidence.
- `session_start_ready:true`, `fallback_ready:true`,
  `single_route_at_risk:false`.
- `broker-session-plan` reports prepared fallback only:
  `same_turn_quota_recovery:false`, `same_thread_quota_recovery:false`,
  `current_process_hotswap:false`, and `unmanaged_tui_hotswap:false`.
- `codex status-latest` still reports `brokered_without_fallback` from a
  rolling local artifact with 224 `200` proxy turns and no quota handoff; it is
  stale relative to route truth and must not be used as fallback-readiness
  proof.
- `daemon status` is still `not_running`,
  `contract:"experimental_socket_stub"`, `hosts_stay_afloat:false`; its fresh
  foreground tick snapshot shows `afloat_with_spare_fallback` but remains
  observational and is not daemon-hosted continuity proof.
- Current gate: cassette capture may proceed only after a just-in-time no-spend
  route refresh reconfirms the spare fallback and the operator explicitly
  approves any live provider-spend capture.

## Workstream 3 - Real Codex Wire Cassettes

Priority: P0 after Workstreams 1 and 2.

Completion metric:

- GitHub `#176` is the active public tracker for real Codex wire cassettes even
  while Linear `TIN-950` is Done.
- Capture preserves SSE streaming shape rather than flattening the behavior
  under test.
- Each captured fixture pins profile, capability, selected account label,
  route-health state, Codex CLI/build identity, and reset-window normalization.
- Non-turn probe traffic is filtered out or explicitly marked as setup noise.
- Raw captures stay out of git. Only scrubbed, fixture-sized JSON with reviewed
  token/account/session/path redaction may be committed.
- Replay failure is diagnostic (`no_cassette_match`, shape drift, or typed
  rejection), not a silent green.

Test commands:

```bash
scripts/capture-codex-wire.sh preflight
scripts/capture-codex-wire.sh review captures/codex-wire-<TS> \
  --require-preflight-ok \
  --require-proxy-meta \
  --require-path-kind responses \
  --require-status 101 \
  --require-status 200 \
  --require-quota-type usage_limit_reached
just smoke-codex-cassette-replay-local
just smoke-codex-cassette-all-exhausted-local
just check-local
git diff --check
```

Todo:

- [ ] Prepare the tracker reconciliation note for `TIN-950` versus `#176`;
  do not post it without explicit operator approval.
- [x] Add a no-spend capture preflight command that records installed
  `oauth-mux` provenance, native Codex version, mitmproxy availability,
  mitmproxy CA readiness, fallback readiness, latest status verdict, and
  stale-process hints before starting the intercepting proxy.
- [x] Add explicit capture review promotion gates for preflight success,
  required endpoint path kinds, required HTTP statuses, and required quota
  `error.type` values.
- [x] Re-run no-spend route truth immediately before capture and keep the
  generated preflight summary with the capture scratch directory.
- [x] Capture one successful live turn with the Codex 0.132
  `/backend-api/codex/responses` WebSocket `101` raw upstream path observed
  and review-gated. This is cassette evidence for upstream shape, not a
  managed WS support claim. Scratch capture:
  `captures/codex-wire-20260526T171741Z` (gitignored, not committed).
- [ ] Capture or explicitly record not-observed status for quota/error shapes:
  `usage_limit_reached`, `usage_not_included`, and all-fallbacks-exhausted.
- [x] Add one scrubbed real-shape replay fixture and wire it into CI-safe
  cassette smoke coverage.

## Workstream 4 - Release, Docs, And Workflow Hygiene

Priority: P1. Release `0.1.12` is shipped; keep docs and install lanes aligned
before expanding public claims.

Completion metric:

- Current-state docs describe `0.1.12` as the latest verified public release
  truth and npm `0.1.9` as a stale package-lane exception.
- Historical docs may keep older versions only when clearly framed as
  historical evidence.
- Manual workflow defaults use the current project version or are deliberately
  documented as historical cleanup targets.
- Release lane docs keep Homebrew binary-only by default and keep managed
  Codex shim behavior opt-in where required.

Test commands:

```bash
scripts/project-version.sh
gh release view v0.1.12 --json tagName,publishedAt,url
npm_config_cache=/private/tmp/omux-npm-cache npm view oauth-mux version
HOMEBREW_NO_INSTALL_FROM_API=1 brew info --json=v2 jesssullivan/omux/oauth-mux | jq -r '.formulae[0].versions.stable'
rg -n "0\\.1\\.[0-8]" README.md docs/productionization-ledger.md docs/adoption.md docs/qa-handoff-matrix.md .github/workflows
git diff --check
```

Todo:

- [x] Update current-state docs and workflow defaults from stale `0.1.7` /
  `0.1.6` / `0.1.0` wording to `0.1.9` where the text is not historical.
- [x] Keep `docs/install-beta-matrix.md` and old release-runbook entries as
  historical evidence unless a fresh parity sweep replaces them.
- [x] Add a short pointer from the productionization ledger to this plan.
- [x] Stage `0.1.10` source/release metadata for the post-`0.1.9` BrokenPipe
  and install-provenance fixes.
- [x] Publish `v0.1.11` GitHub Release assets and update the public Homebrew tap
  to `0.1.11`; npm remains blocked/stale at `0.1.9`.
- [x] Publish `v0.1.12` GitHub Release assets and update the public Homebrew tap
  to `0.1.12`; npm remains blocked/stale at `0.1.9`.
- [x] Fix the post-release Homebrew checksum drift and verify
  `brew fetch --force jesssullivan/omux/oauth-mux` passes against the public
  tap.
- [x] When running the stale-version search, confirm remaining older-version
  hits are explicitly historical, such as the 2026-05-17 no-spend snapshot or
  the `0.1.1` npm deprecation cleanup workflow.

## Workstream 5 - Tracker Hygiene

Priority: P1 after local facts are current.

Completion metric:

- GitHub issues, Linear tickets, and repo docs tell the same story about what
  is proven, what remains open, and what is only diagnostic infrastructure.
- No discussion or tracker comment is posted from this plan without explicit
  operator approval.
- The `TIN-950` Done / `#176` open mismatch is resolved by either reopening or
  clarifying Linear, or by closing `#176` only after real cassette acceptance is
  actually complete.

Todo:

- [x] Draft tracker update text locally for `#176`, `#212`, `#67`, `#68`, and
  `#163`.
- [x] Re-check GitHub open issues/open PRs and Linear ticket states read-only.
- [ ] Ask before posting or changing Linear/GitHub state.
- [ ] Keep `#163` and `#68` scoped as later work, not blockers for the
  BrokenPipe/cassette path.

Local draft: `docs/tracker-updates/2026-05-20/README.md`.

## Workstream 6 - Codex Remote App-Server Sidecar

Priority: later this week after Workstreams 1-3 are stable.

Completion metric:

- A no-spend sidecar smoke proves loopback transport, remote auth token
  handling, connection ordering, and TUI attachment without live provider
  calls.
- The prototype records whether `thread/start`, `thread/list`,
  `thread/resume`, `account/read`, and error/rate-limit surfaces are observable
  enough for managed interactive UX.
- Docs state whether the sidecar can become the managed TUI path or remains
  experimental.

Todo:

- [ ] Keep `TIN-938` / GitHub `#163` scoped to no-spend connection smoke first.
- [ ] Do not claim managed interactive UX or live sidecar spend proof until a
  separate explicit acceptance run exists.

## Workstream 7 - Non-Codex Provider Proof

Priority: later this week / secondary until Codex reference adapter hardening is
stable.

Completion metric:

- One non-Codex provider has fixture-backed positive and negative proof through
  the provider-authoring checklist.
- The provider support matrix distinguishes schema-modeled, no-spend proven,
  fixture-backed, and live-proven states.
- No non-Codex stay-afloat, background daemon, or universal provider claim is
  made before live adapter proof.

Todo:

- [ ] Keep `TIN-736` / GitHub `#68` open and secondary.
- [ ] Pick the next provider by narrowest no-spend truth surface; likely Claude
  auth-status first, then MCP/Figma/Linear only when official auth/failure
  boundaries are pinned.
- [ ] Add fixtures and docs before any public support copy is upgraded.

## Execution Order

Recommended landing slices:

- Slice A, focused reliability PR: `src/adapters/codex/main.zig`,
  `src/adapters/codex/wire_proxy.zig`, `scripts/test-stub-codex.py`,
  `scripts/test-stub-upstream.py`, and
  `scripts/smoke-codex-provider-degraded.sh`. Completion metric is Workstream 1
  green with `just check-local` and `git diff --check`. Local commit:
  `5bd36b3 fix: classify codex stream disconnects`.
- Slice B, docs and release hygiene PR: workflow default-version updates,
  README/adoption/QA/ledger refreshes, this plan, and local tracker drafts.
  Completion metric is stale-version search showing only historical older
  versions plus `git diff --check`.
- Slice C, real cassette PR: starts only after Slice A lands and a just-in-time
  no-spend route refresh confirms spare fallback. Requires explicit operator
  approval for any provider-spend capture.
- Slice D, later sidecar/provider work: Workstreams 6 and 7 remain secondary
  until the Codex reference adapter has the BrokenPipe and cassette evidence
  stabilized.

1. Land Workstream 1 as a focused BrokenPipe reliability PR.
2. Refresh Workstream 2 no-spend route/process truth.
3. Run Workstream 3 real cassette capture and replay hardening.
4. Keep Workstream 4 hygiene moving in small docs/workflow patches.
5. Reconcile tracker state after the facts are refreshed.
6. Start Workstream 6 sidecar no-spend prototype later this week.
7. Start Workstream 7 non-Codex provider proof only after Codex evidence is
   stable enough to be the reference path.
