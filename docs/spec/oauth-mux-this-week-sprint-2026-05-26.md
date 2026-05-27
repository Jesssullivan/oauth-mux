# oauth-mux This-Week Sprint
Date: 2026-05-26
Target window: 2026-05-26 through 2026-05-31
Status: active sprint todo list; subordinate to `AGENTS.md`,
`docs/spec/broker-mcp-contract-2026-05-03.md`,
`docs/spec/codex-adapter-contract-2026-05-03.md`, and
`docs/spec/oauth-mux-operational-hardening-plan-2026-05-20.md`.

## Sprint Goal

Convert the `0.1.12` release into reliable next evidence: clean dogfood
baselines, real Codex cassette coverage, and a disciplined backlog that does
not expand public claims ahead of proof.

The product anchor stays unchanged: `oauth-mux codex` must keep a managed
Codex harness usable when auth, quota, tier, or local runtime state changes.
Restart, supervised relaunch, broad daemon claims, and schema-modeled provider
support are not success metrics.

## Current Truth

- `oauth-mux` main is clean and synced to `origin/main` at `01b4069`
  after PR #305 exposed legacy Codex resume namespace diagnostics.
- `../lab` main is clean and synced to `origin/main` at `3d9aef59`
  after PR #510 updated the Home Manager oauth-mux pin to the PR #305
  source revision.
- Public release `v0.1.12` is published and verified for GitHub Release,
  Homebrew, user-local dogfood, curl installer assets, deb/rpm assets, and the
  lab Home Manager source pin.
- npm remains stale at `0.1.9`; do not claim npm `0.1.12`.
- Current real-host Codex preflight reports `fallback_ready:true`,
  `selectable_routes:2`, `selectable_fallback_routes:1`,
  `session_start_ready:true`, `single_route_at_risk:false`,
  `spends_provider_calls:false`, and `mutates_route_health:false`.
- Current route matrix selects `codex:max-1#codex-max`, keeps `max-4`
  as the selectable fallback, and leaves `max-2` and `max-3` blocked as
  `quota_exhausted` until their reset windows.
- `TIN-1591` remains contained, not resolved. Fresh process/fd snapshot
  `process-snapshot-20260527T124603Z-cassette-gate-20260527` recorded
  `nofile.soft:256`, `process_count:765`, `managed_codex_children:3`,
  `active_codex_or_oauth_mux_processes:7`,
  `orphan_listener_candidate_count:3`, and `max_fd_soft_limit_pct:68.8`.
  The gate admits local release validation, but blocks unannotated live
  reliability and quota-cassette claims until active sessions/listeners are
  closed or explicitly accounted for.
- GitHub `#176` remains open even though Linear `TIN-950` is Done. Treat that
  as a tracker mismatch until real quota/error cassettes land or Linear is
  explicitly clarified.
- Live regression found after `0.1.11`: native `codex resume` and
  `oauth-mux codex resume` used the same SQLite authority and cwd, but Codex
  filtered picker rows by `threads.model_provider`; the managed
  `oauth_mux_openai` provider created a shadow resume namespace. P0 fix is to
  keep `model_provider = "openai"` and route through mux with `openai_base_url`.
- Local P0 proof on 2026-05-26: `just test`,
  `just smoke-codex-cli-ux-local`, local dogfood reinstall, and a live
  `/Users/jess/git/blahaj` resume-picker check all passed with managed resume
  showing the same `[Cwd]` rows as native Codex.
- PR #305 added non-mutating diagnostics for legacy
  `oauth_mux_openai` resume rows. It does not rewrite SQLite; any repair must
  be operator-explicit and backed up.

## Workstream P0 - Resume Picker Namespace Parity

Priority: P0 before cassette or live reliability claims.

Completion metric:

- Managed generated config keeps Codex's native provider namespace:
  `model_provider = "openai"`.
- Managed generated config routes provider traffic through localhost
  `openai_base_url` without writing canonical `~/.codex/config.toml`.
- The proxy maps built-in provider paths such as `/backend-api/responses` and
  `/backend-api/models` to the ChatGPT Codex upstream path shape.
- Native and managed `codex resume` show the same `[Cwd]` picker rows for the
  same working directory.
- CI smoke fails if the shadow `oauth_mux_openai` provider returns to generated
  config.

Todos:

- [x] Patch generated config and proxy path mapping.
- [x] Extend smoke/stub assertions for native provider namespace plus proxy URL.
- [x] Re-run `just test` and `just smoke-codex-cli-ux-local`.
- [x] Reinstall the fixed binary locally and verify the live picker from a repo
  with known native and managed rows.
- [x] Update the release/HM plan after the fix lands on a clean public ref.

## Non-Goals

- Do not close `#176` from a successful-turn cassette alone.
- Do not promote daemon, sidecar, same-thread, or unmanaged hot-swap claims.
- Do not start `#163` live sidecar spend proof this week.
- Do not expand non-Codex provider claims before Codex cassette evidence is
  stronger.
- Do not delete divergent local branches without preserving or explicitly
  retiring their work.

## Workstream A - TIN-1591 Process/FD Hygiene

Priority: P0.

Completion metric:

- A repeatable process/fd snapshot routine exists for dogfood evidence sessions.
- The routine records soft fd limit, active oauth-mux/Codex process counts,
  managed children, listener candidates, duplicate helper groups, and explicit
  cleanup eligibility.
- At least two snapshots from a clean baseline agree enough to distinguish
  normal agent fanout from leak/process residue.
- Cleanup rules require exact operator approval before killing active Codex,
  Claude, MCP, or browser helper processes.

Todos:

- [x] Add a short `TIN-1591` runbook section to `docs/dogfood-process-fanout.md`
  or a sibling doc with the exact snapshot command, interpretation rules, and
  cleanup approval policy.
- [x] Re-run `python3 scripts/dogfood-process-snapshot.py --json` from a clean
  shell and save only a redacted summary if it changes the claim posture.
- [x] Decide whether the soft fd limit `256` is acceptable for dogfood evidence
  or whether the runbook must require a higher limit. Decision: `256` is not
  acceptable for broad live reliability or quota-cassette claims when the fresh
  snapshot already shows 73.4% of the soft limit and active agent fanout.
  Proceed only with explicitly annotated local evidence, or raise the limit and
  collect a cleaner repeated baseline before live claims.
- [x] Define which process classes are never killed by automation.
- [ ] Re-check no proxy/capture/long-running validation processes before each
  live or cassette run.

Validation:

```bash
python3 scripts/dogfood-process-snapshot.py --json \
  | jq '{summary, process_summary, safe_cleanup, mutates_processes, spends_provider_calls}'
pgrep -fl 'mitmdump|capture-codex-wire|gh run watch|nix build .#checks.aarch64-darwin.fish-syntax-test' || true
git diff --check
```

## Workstream B - GitHub #176 / Linear TIN-950 Cassettes

Priority: P0 after Workstream A baseline is clean enough.

Completion metric:

- Capture review requires proxy metadata and installed preflight proof.
- At least one scrubbed real-shape replay fixture is committed.
- Quota/error shapes are captured or explicitly marked not observed:
  `usage_limit_reached`, `usage_not_included`, all-fallbacks-exhausted, and
  auth/error-path drift.
- Replay fails diagnostically on shape drift.

Known evidence:

- Scratch capture `captures/codex-wire-20260526T171741Z` exists locally and
  is gitignored. It is useful raw normal-turn evidence for Codex 0.132
  WebSocket `101` behavior, but it is not a fixture candidate: the current
  reviewer rejects it because `x-codex-turn-metadata` still contains a local
  workspace path in the per-flow JSON.
- Current-release auth-failure scratch capture
  `captures/codex-wire-20260526T193856Z` exists locally and is gitignored;
  it observed `refresh_token_reused` on `/oauth/token` and `token_expired`
  on `/backend-api/codex/responses`, with same-run proxy metadata and no
  review failures after the local-path redaction addon fix.
- PR #299 promoted a scrubbed auth-failure fixture from that run and wired it
  into CI-safe capture-review and replay smokes. The committed fixture
  deliberately sanitizes secret-shaped strings and local paths; the raw
  capture remains gitignored.
- Codex 0.132 `/backend-api/codex/responses` was observed as a WebSocket `101`,
  not a simple `200` SSE-only path. The earlier raw capture remains
  unpromotable, but the 2026-05-27 broker-owned capture below is now the
  promoted fixture for the normal WebSocket upgrade shape.
- Current-release broker-owned scratch capture
  `captures/codex-wire-20260527T133757Z` exists locally and is gitignored;
  it was captured from `oauth-mux codex broker-run --confirm-spend`, completed
  one live provider turn, and passed the current proxy-meta and redaction
  gates with `/backend-api/codex/responses -> 101`.
- The scrubbed fixture
  `test/fixtures/codex-wire/broker-owned-websocket-success/` now preserves
  that normal WebSocket upgrade shape and is covered by capture-review and
  cassette-replay smokes.
- Cookie and `Set-Cookie` redaction is now review-gated after PR `#292`.
- Local workspace path redaction is review-gated before fixture promotion.
- No quota/exhaustion shapes have been captured yet.

Todos:

- [ ] Run a just-in-time capture preflight before any proxy.
- [x] Recapture a successful-turn cassette with current local-path redaction
  before promoting any normal-turn WebSocket fixture.
- [ ] Target quota/error capture with current fallback capacity and capture
  provenance, not from a single-route-at-risk state.
- [x] Promote the smallest scrubbed fixture that proves the real path shape.
- [x] Add or extend CI-safe replay smoke coverage for the scrubbed fixture.
- [x] Gate obvious local home/tmp paths before any cassette fixture promotion.
- [ ] Reconcile `TIN-950` Done versus GitHub `#176` open after the fixture and
  error-shape decision are recorded.

Validation:

```bash
scripts/capture-codex-wire.sh preflight
scripts/capture-codex-wire.sh review captures/codex-wire-<TS> \
  --require-preflight-ok \
  --require-proxy-meta \
  --require-path-kind responses \
  --require-status 101 \
  --require-status 200
python3 -m py_compile scripts/review-codex-wire-capture.py scripts/codex-wire-addon.py
./scripts/smoke-codex-capture-review.sh
just smoke-codex-cassette-replay-local
git diff --check
```

## Workstream C - GitHub #212 / Linear TIN-1079 Exhaustion Matrix

Priority: P1, only after Workstream A and enough Workstream B evidence.

Completion metric:

- `TIN-1079` moves from Backlog only when fallback capacity is current and the
  run has clear capture provenance.
- The matrix separates route inventory, provider probes, and actual engineered
  exhaustion.
- Evidence records selected route, fallback pool, reset-window normalization,
  and whether route health was mutated.

Todos:

- [x] Refresh route inventory with `accounts list`, `route explain`,
  `codex preflight`, and `broker-session-plan`.
- [ ] Identify one intentionally exhausted or limited route and one credited
  fallback route for a controlled run.
- [ ] Define stop conditions before the run: single-route-at-risk, missing
  fallback, proxy redaction failure, or TIN-1591 contamination.
- [ ] Record whether the test is allowed to mutate route health.
- [ ] Update `TIN-1079` with the exact current matrix before live execution.

Validation:

```bash
oauth-mux accounts list --provider codex --json
oauth-mux route explain --profile codex-max --capability codex-max --json
oauth-mux codex preflight --profile codex-max --capability codex-max --json
oauth-mux codex broker-session-plan --profile codex-max --capability codex-max --json
```

## Workstream D - Doc Accuracy And Release Hygiene

Priority: P1.

Completion metric:

- Current-state docs consistently say `0.1.12` is published for GitHub Release
  and Homebrew, while npm is stale at `0.1.9`.
- Historical snapshots remain clearly historical.
- `SHA256SUMS.full` semantics are explicit before `0.1.12`: it remains a
  checksum manifest for publishable payloads listed in `publish-files.txt`, not
  for the generated handoff metadata files themselves.
- Public copy does not claim non-Codex stay-afloat, daemon beta, sidecar UX, or
  npm `0.1.12`.

Todos:

- [x] Audit current-state docs for stale `0.1.10` / staged `0.1.11` language.
- [ ] Mark older preflight snapshots as historical where they still mention
  outdated selected routes or stale installed binaries.
- [x] Decide whether `SHA256SUMS.full` must include `publish-files.txt` and
  `release-handoff.md`.
- [x] Add a release hygiene todo for npm auth or explicitly keep npm out of the
  `0.1.12` public claim.

Validation:

```bash
rg -n "0\\.1\\.10|0\\.1\\.11 is the next staged|v0\\.1\\.10|npm.*0\\.1\\.12" \
  README.md docs .github scripts || true
npm_config_cache=/private/tmp/omux-npm-cache npm view oauth-mux version --json
HOMEBREW_NO_INSTALL_FROM_API=1 brew info jesssullivan/omux/oauth-mux --json=v2 \
  | jq '.formulae[] | {stable: .versions.stable, installed: [.installed[]?.version]}'
git diff --check
```

## Workstream E - GitHub #163 / Linear TIN-938 Sidecar

Priority: P2, constrained.

Completion metric:

- A local loopback smoke proves sidecar process lifecycle, local transport,
  connection ordering, and attach/readiness semantics.
- No live sidecar provider call is made.
- Docs explicitly classify the sidecar as exploratory until cassette evidence
  and quota/error replay coverage are stronger.

Todos:

- [ ] Read upstream Codex 0.132 app-server/remote attach behavior before
  writing code.
- [ ] Define a loopback-only fixture or stub for transport and readiness.
- [ ] Add a smoke name and acceptance text without claiming managed TUI UX.

## Workstream F - GitHub #68 / Linear TIN-736 Provider Proof

Priority: P2/P3, secondary to Codex.

Completion metric:

- One next provider is admitted through the provider-authoring checklist with
  fixture-backed positive and negative proof.
- Provider matrix distinguishes schema-modeled, fixture-backed, and live-proven
  states.

Todos:

- [ ] Choose the next provider only after Codex cassette acceptance is stronger.
- [ ] Prefer Claude command-owned auth-status proof before broader OAuth
  providers.
- [ ] Keep Figma/MCP provider proof under separate tickets; do not roll it into
  Codex continuity claims.

## Branch/Worktree Hygiene Parking Lot

These are organizational tasks, not product blockers.

- [ ] oauth-mux: classify local merged/superseded branches before deletion.
- [ ] lab: retire merged `codex/oauth-mux-fish-path-precedence` only after
  operator approval.
- [ ] homebrew-omux: preserve or retire divergent local `main` and old `0.1.9`
  tap branches before any reset.

## Sprint Exit Criteria

- TIN-1591 has a runbook and at least one fresh clean-baseline snapshot.
- #176 has either a scrubbed real-shape fixture PR or a recorded blocker with
  exact missing evidence.
- #212 has a current route matrix and a clear go/no-go gate for provider-call
  execution.
- Docs no longer imply `0.1.11` is current for resume picker parity or that npm
  is current.
- No new public continuity claims are made beyond the evidence above.
