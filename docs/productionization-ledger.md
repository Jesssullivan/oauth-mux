# Productionization Ledger

Updated: 2026-07-04

This ledger is the short operator map for oauth-mux productionization. It is
subordinate to the broker contract and Codex adapter contract, and it should be
refreshed when release truth, route evidence, or tracker state changes.

## Current Snapshot

- Release state: `v0.1.14` ("keepalive") is the current release line, cut from
  `build.zig.zon` version `0.1.14`. It is the first release carrying the
  `oauth-mux keepalive` warm loop (proactive per-account credential refresh at
  ~75% token lifetime, consent-gated via `allow_proactive_refresh`, default
  false), the keepalive safety rails (shared-identity exclusion with
  first-refresh stagger, broker identity dedupe before election, the
  in-process actor gate on the repair-lock registry), operator-explicit
  `just keepalive-service-install` launchd/systemd unit templates, and
  isolated-browser Claude login helpers. See `CHANGELOG.md` for the
  evidence-bound claim list. Prior release `v0.1.13` (`4a7d02b`) carried the
  TIN-1851 home-is-store session-authority default (#367/#370), the flock
  unlink-on-release race fix with the macOS runtime-dir move (#379, TIN-2041),
  the default-mode native resume chooser (#380, TIN-2045), corrected Claude
  OAuth endpoint constants (#381, TIN-1817), the bounded repair-events log
  (#369), and the remote-first proof policy (#368/#372); it was cut behind a
  green remote release-proof on the GloriousFlywheel runner and a committed
  clean-lineage live e2e (`docs/evidence/codex-live-e2e-clean-lineage-20260612/`).
- CI/release state: GitHub Actions is the live source for release proof. The
  v0.1.14 remote release proof passed (GloriousFlywheel job `85131314417`,
  `release-proof` lane, 11m31s) on branch `jess/release-v0.1.14`; the release
  PR (#441) and the tag/publish step that produces the 23-asset GitHub Release
  matrix are pending as of this snapshot. Once merged and tagged, update this
  bullet with the release workflow run id and confirm the release is
  non-draft/non-prerelease, matching the v0.1.13 precedent (workflow
  `27432964644`). The npm lane is RETIRED (operator decision 2026-06-12,
  TIN-2042): packaging truth moves to the Bazel SSOT and its derived lanes,
  which exclude npm; the published npm package remains stale at `0.1.9` and
  cannot be deprecated until/unless a registry token is ever rotated.
- Version truth: source version is `0.1.14`. GitHub Release, curl installer
  assets, deb/rpm assets, and the public Homebrew tap should resolve to
  `0.1.14` once the pending publish step completes; see
  `docs/install-beta-matrix.md` for per-lane re-verification status (rows are
  marked pending, not Pass, until each lane is actually re-run at 0.1.14). The
  npm lane is retired. The Homebrew formula remains binary-only by default and
  must not install or link a managed `codex` shim.
- Installed provenance: continue checking `which -a oauth-mux`, `which -a
  codex`, `oauth-mux version --json`, and `codex preflight` before treating
  any installed-command run as release evidence. Upgrade note: v0.1.13 moved
  the macOS runtime dir off /tmp; v0.1.14 adds the keepalive warm loop
  (consent-gated, off by default). Restart long-lived managed sessions and any
  daemon after upgrading so all lock holders converge on the new runtime-dir
  path and any newly opted-in keepalive config takes effect.
- Homebrew truth: the public `jesssullivan/omux` tap last verified against
  `oauth-mux 0.1.13` (`Formula/oauth-mux.rb` updated with checksums from the
  published v0.1.13 GitHub Release artifacts); the v0.1.14 tap update is
  pending the release publish step. Re-verify per
  `docs/install-beta-matrix.md` before treating the tap as resolved to
  `0.1.14`. Homebrew is a binary-only package lane by default: QA must prove it installs
  `oauth-mux`, does not install an `OMUX_CODEX_SHIM`, and leaves native `codex`
  command resolution unchanged.
- Codex route truth: the 2026-05-26 local preflight uses user-local
  post-PR #295 oauth-mux and native Codex outside oauth-mux. It reports
  `ok:true`, `session_start_ready:true`, `fallback_ready:true`,
  `selectable_fallback_routes:2`, `single_route_at_risk:false`,
  `spends_provider_calls:false`, and `mutates_route_health:false`.
- Process/fd truth: TIN-1591 remains contained, not resolved. Current snapshots
  still show active Codex/oauth-mux fanout, a soft fd limit of `256`, and
  orphan-listener candidates. The latest gate snapshot
  `process-snapshot-20260527T144821Z-tin1591-gate-20260527` has max visible fd
  use at 43.4% of the collector soft limit, so the current blocker is process
  topology rather than fd pressure. Treat dogfood evidence as local
  release/install validation only until repeated clean-baseline snapshots
  support broader live reliability claims.
- Daemon truth: `oauth-mux daemon status --json` still reports
  `status:"not_running"`, `contract:"experimental_socket_stub"`, and
  `hosts_stay_afloat:false`; its foreground tick snapshot is observational only
  even when fresh and showing `afloat_with_spare_fallback`. The beta daemon lane
  must host the same foreground tick engine and must not claim unmanaged
  hot-swap.
- Codex shim truth: package/user-local installs can make future bare `codex`
  commands enter `oauth-mux codex` when PATH resolves the shim, but that is not
  a global stay-afloat daemon and does not protect direct native Codex binaries
  or already-running unmanaged sessions.
- Nix/Home Manager truth: source now exposes a binary-only
  `packages.<system>.oauth-mux` package, the existing shimmed
  `packages.<system>.withCodexShim` / default package, and a Home Manager module
  that defaults to binary-only unless `programs.oauth-mux.codexShim.enable =
  true`.

## Feature Ledger

| Feature | Current level | Notes |
| --- | --- | --- |
| Managed Codex launch/resume | Live-proven | Reference adapter path for `oauth-mux codex` and `oauth-mux codex resume`. |
| Codex quota handoff | Live-proven for managed Codex | Strongest preserved proof lives in `docs/evidence/codex-engineered-quota-handoff-20260509/`. |
| Session authority model | Codex-implemented, shifted by TIN-1851 | Current managed Codex defaults to route-local persistent account homes: the selected route home is `CODEX_HOME` and owns muxed `state_5.sqlite*` / `logs_2.sqlite*`. Legacy canonical bridge / `CODEX_SQLITE_HOME` behavior is explicit `shared_canonical` opt-in only. |
| Resume picker namespace parity | Published | PR #295 keeps managed Codex on the built-in `openai` provider namespace while routing through mux via `openai_base_url`, so native and managed `codex resume` enumerate the same provider-filtered session rows. Published in `0.1.12`. |
| Config/TOML preservation | Implemented | Root-partitioned Codex config passthrough keeps user settings, MCP servers, profiles, model defaults, approval/sandbox policy, and non-managed provider definitions. |
| Experimental Codex settings injection | Implemented | Defaults can be injected without treating user config as disposable. |
| Native Codex shim pass-through | Implemented | Admin/login/help/version paths bypass route election and exec native Codex. Public Homebrew remains binary-only and must not install the shim by default. |
| Home Manager lane | Implemented in source | Module defaults to binary-only install; managed `codex` shim is explicit opt-in. |
| Route-health recovery | Implemented | Transient provider degradation can recover after retry windows without becoming permanent auth death. Source after PR #279 also separates downstream client disconnects from upstream/provider failures so client `BrokenPipe` does not poison route health. |
| Redacted diagnostics and tracing | Implemented | JSON diagnostics and `OMUX_TRACE=1` support route/session/auth/runtime debugging without token, raw account id, session id, or path leakage. |
| Agent-safe reauth mediation | Contracted, partial surfaces | CLI JSON exposes consent/action fields and safe handoff-plan commands for upstream-owned login surfaces; future MCP tools must mirror CLI semantics. |
| Beta daemon | Socket stub (non-functional) | Foreground tick engine and daemon-hosted beta may mediate status/handoffs; not a hidden dependency and not unmanaged hot-swap. |
| Claude adapter | Synthetic smoke only | `auth-status` and account-store isolation are the first proof lane; no Claude stay-afloat claim. |
| OMO, Pi, OpenCode, Kimi | Adapter-candidate only | Adjacent agent-control-plane proof does not equal oauth-mux keepalive support. |

## UX, DX, AX Stance

UX:

- The managed harness should feel like the upstream harness.
- Handoffs are labeled and user-mediated when upstream auth is required.
- A daemon beta may improve observation and mediation, but current Codex UX must
  not depend on a hidden background service.

DX:

- `just build`, `just test`, `just check`, and `just e2e` dispatch remote
  development proof gates on GloriousFlywheel.
- `just remote-build`, `just remote-test`, `just remote-check`, and
  `just remote-e2e` remain explicit aliases for the same remote lanes.
- `just release-proof <version> [ref]` or
  `just remote-release-proof <ref> <version>` is required before any registry
  mutation.
- Local `*-local` build/check commands are debugging tools only; do not use them
  as PR, release, or dogfood readiness proof on developer laptops.
- Installed-command dogfood must use `oauth-mux version --json`,
  `which -a oauth-mux`, `which -a codex`, and `codex preflight` to prove the
  exact binary and shim path under test.

AX:

- Agents use local inspection surfaces first: `discover`, `providers list`,
  `accounts list`, `doctor runtime`, `route explain`, `repair-plan`,
  `stay-afloat --once`, `codex preflight`, `status-latest`, and
  `daemon status`.
- Agents must not read token files, run upstream login, spend provider calls, or
  mutate credential stores without explicit consent.
- Trace and status artifacts are support material only after redaction review.
- Agent process fanout evidence lives in `docs/dogfood-process-fanout.md` and
  `scripts/dogfood-process-snapshot.py`; it is observational only and must not
  kill processes, spend provider calls, or be cited as route-selection proof.

## Adapter Strategy

Codex remains the reference adapter until its negative/cassette matrix and
release truth are stable. Claude is the next likely adapter proof because it has
a narrow command-owned `auth-status` surface and account-store isolation to
validate. The broker MCP contract now has a synthetic Claude-shaped smoke, but
that only validates provider-neutral account/session/error semantics; it is not
a Claude stay-afloat or `oauth-mux claude` claim. OMO, Pi, OpenCode, and Kimi
should first get adapter contracts that answer token shape, auth storage, reload
boundary, quota signal, failure signal, wire interception, process topology, and
session authority. Until then, they may consume oauth-mux diagnostics or future
MCP repair prompts, but oauth-mux must not claim to keep them alive.

## Active Plan

The current testable workstream plan lives at
`docs/spec/oauth-mux-operational-hardening-plan-2026-05-20.md`. The BrokenPipe
regression fix and Codex 0.132 resume authority fix are published in the
current public release. The immediate operational risk is no longer stale
install provenance; it is process/fd fanout contaminating dogfood evidence and
the remaining lack of quota/error real cassettes. Next work should prioritize
TIN-1591 cleanup policy, real Codex quota/error cassettes, the #176/TIN-950
tracker mismatch, then later sidecar and non-Codex provider work.

## Release And Distribution Posture

`v0.1.14` ("keepalive") is the current release line. It carries the
`oauth-mux keepalive` warm loop, its safety rails (shared-identity exclusion,
identity dedupe before election, the in-process actor gate on the repair-lock
registry), operator-explicit `just keepalive-service-install` unit templates,
and isolated-browser Claude login helpers — see `CHANGELOG.md` for the full
evidence-bound claim list. The v0.1.14 remote release proof passed
(GloriousFlywheel job `85131314417`, `release-proof` lane, 11m31s) on branch
`jess/release-v0.1.14`; the tag/publish step that produces the GitHub Release,
updates the public Homebrew tap, and republishes deb/rpm assets runs once the
release PR (#441) merges to `main`. Do not treat any install lane as resolved
to `0.1.14` until `docs/install-beta-matrix.md` shows that lane re-verified,
not merely pending.
Prior release `v0.1.12` carried Codex 0.132 resume authority parity for
`logs_2.sqlite*` / `CODEX_SQLITE_HOME`, the #176 capture-review
`--require-proxy-meta` gate, and PR #295's provider-namespace resume picker
fix; release workflow `26469045026` published that GitHub Release
non-draft/non-prerelease with 23 assets, the public Homebrew tap updated to
`0.1.12`, and Lab PR #507 pinned the Home Manager source lane to that release
commit with `codexShim` disabled. Release `v0.1.13` (`4a7d02b`) followed with
the TIN-1851 home-is-store default and the fixes listed in the Current
Snapshot block above.
Negative Codex cassettes, broader adapter proof, and daemon beta truth remain
follow-up work.
Windows managed-`codex` parity is unassigned since the npm wrapper lane was
retired (2026-06-12); a Windows lane decision rides the Bazel SSOT work
(TIN-2046/TIN-2050) if a native Windows operator need is ever proven.
Future public install copy must avoid claiming a version or lane behavior until
that version is actually published and verified.

The release lanes remain:

- worktree dogfood;
- user-local dogfood;
- Nix package;
- Homebrew;
- deb/rpm packages;
- Home Manager.

Remote/browser validation should use the repo's remote execution lane when a
browser is needed; local Playwright is not part of this CLI proof path.

## Tracker Map

| Theme | Linear | GitHub | Current stance |
| --- | --- | --- | --- |
| Broker daemon and adapter contract | TIN-738 | #67 | Anchor remains open until daemon beta and second-adapter validation are honest. |
| Codex next-turn broker switch | TIN-916 | #131 | Closed for the proven managed Codex live handoff. Remaining negative/permutation work lives in #212/#176; same-thread, mid-turn, and unmanaged daemon behavior remain separate non-claims. |
| Upstream Codex usage-limit hook | TIN-939 | #164 | Draft proposal written; use it to request a first-class external-auth usage-limit handoff hook while keeping oauth-mux claims scoped to proven managed-proxy behavior. |
| Live Codex account-swap acceptance | TIN-951 | #177 | Done for managed Codex; strongest preserved proof is `docs/evidence/codex-engineered-quota-handoff-20260509/`. |
| Wire cassette coverage | TIN-950 | #176 | PR #299 promoted a scrubbed current-release auth-failure fixture and replay smoke. Quota/rate-limit and all-fallbacks-exhausted cassette evidence is still needed before treating negative permutations as stable release proof. Linear currently marks TIN-950 Done while GitHub #176 remains open; reconcile this tracker inconsistency immediately — real cassette acceptance is a separate release-readiness gate, not a precondition for the tracker correction. |
| Harness session authority bridge | TIN-979 / TIN-1624 / TIN-1851 | #191 / #288 / #367 | Original canonical bridge work is historical. Current main defaults to home-is-store / route-local persistent Codex authority; `shared_canonical` remains explicit opt-in. Future cross-harness authority work stays under #67/#68. |
| Codex session-store portability | TIN-936 / TIN-1851 | #161 / #367 | Policy is explicit: default muxed sessions live in route-local persistent account homes; canonical bridge is opt-in; silent session-store copy/import is rejected until a separate confirmed import command exists. |
| OTEL-friendly tracing | TIN-1148 | PR #225/#226 lineage | Implemented trace schema should become the standard support-bundle path. |
| Package parity and install lanes | TIN-1255 | #252 | `v0.1.14` is the current release line (GF release-proof job `85131314417` passed on `jess/release-v0.1.14`); re-verify each lane in `docs/install-beta-matrix.md` once release PR #441 publishes GitHub Release, Homebrew, curl installer, and deb/rpm assets. npm retired (TIN-2042): the registry package stays stale at `0.1.9` by design, with `npm-deprecate.yml` keeping it dead. |
| Home Manager and Windows shim parity | not assigned | #257 | Home Manager source lane is implemented with opt-in shim; Windows raw tarballs stay binary-only and npm is the managed-shim lane. |
| Provider proof beyond Codex | TIN-736 | #68 | Claude next; other agents stay adapter-candidate only. |
| Website truth refresh | TIN-734 / TIN-925 | external site repo | `omux.xoxd.ai` source lives outside this repo and must be refreshed from the ledger, QA matrix, and install-lane docs. |

## Acceptance Gates

- Local state refresh passes with current installed binary:
  `doctor`, `providers list`, `accounts list`, `route explain`,
  `codex preflight`, `broker-session-plan`, `stay-afloat next`,
  `status-latest`, and `daemon status`.
- Remote validation passes: `just remote-check`, plus targeted remote lanes such
  as `just remote-test`, `just remote-build`, and `just remote-e2e` when the
  change warrants them. Local validation commands are debugging aids only.
- Dogfood process/memory concerns are backed by at least two redacted
  `dogfood-process-snapshot` artifacts before being called leaks.
- Public release validation passes: `just remote-release-proof <ref> <version>`,
  release proof workflow, npm dry run/publish workflow as appropriate, Homebrew
  QA, and system package QA.
- Homebrew release validation proves both installed binary output and
  `brew info --json=v2` stable version semantics for the public tap formula.
- Public copy does not claim same-thread continuity, mid-turn recovery,
  unmanaged daemon hot-swap, non-Codex stay-afloat, universal provider support,
  or future package availability before publication.
