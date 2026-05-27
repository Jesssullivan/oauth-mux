# Productionization Ledger

Updated: 2026-05-26

This ledger is the short operator map for oauth-mux productionization. It is
subordinate to the broker contract and Codex adapter contract, and it should be
refreshed when release truth, route evidence, or tracker state changes.

## Current Snapshot

- Release state: `v0.1.12` points at `38ac7e0`, including the
  BrokenPipe/client-disconnect hardening from PR #279, the Codex 0.132 SQLite
  resume authority fix from PR #289, the Codex capture-review proxy metadata
  gate from PR #290, the `0.1.11` release from PR #291, the post-release
  capture cookie redaction hardening from PR #292, and the provider-namespace
  resume picker parity fix from PR #295, followed by the `0.1.12` release prep
  from PR #296. Main after the release also includes PR #299, which promoted a
  scrubbed auth-failure cassette fixture and local-path redaction gate; that
  follow-up is not part of the published `0.1.12` release.
- CI/release state: GitHub Actions is the live source for release proof. Release
  workflow `26469045026` published `v0.1.12`; release assets are present and
  the public GitHub Release is non-draft/non-prerelease. npm dry-run/publish
  remains blocked/stale; npm `latest` still reports `0.1.9`.
- Version truth: source version is `0.1.12`. GitHub Release, curl installer
  assets, deb/rpm assets, public Homebrew tap, user-local dogfood, and the lab
  Home Manager source lane resolve to `0.1.12`. npm remains stale at `0.1.9`.
  The Homebrew formula remains binary-only by default and must not install or
  link a managed `codex` shim.
- Installed provenance: user-local dogfood is PATH-first in the oauth-mux repo
  shell and reports `0.1.12` with build id `v0.1.12`; Homebrew also reports
  `0.1.12`. Continue checking `which -a oauth-mux`, `which -a codex`,
  `oauth-mux version --json`, and `codex preflight` before treating any
  installed-command run as release evidence.
- Homebrew truth: the public `jesssullivan/omux` tap advertises `oauth-mux
  0.1.12`, the local linked keg is `0.1.12`, and
  `brew fetch --force jesssullivan/omux/oauth-mux` passes after tap PR #10
  corrected checksums against the published GitHub Release artifacts.
  Homebrew is a binary-only package lane by default: QA must prove it installs
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
| Session authority bridge | Implemented | Managed auth/config overlays bridge canonical Codex session authority, including `state_5.sqlite*` and `logs_2.sqlite*` when present, with canonical `CODEX_SQLITE_HOME` for Codex 0.132+. |
| Resume picker namespace parity | Published | PR #295 keeps managed Codex on the built-in `openai` provider namespace while routing through mux via `openai_base_url`, so native and managed `codex resume` enumerate the same provider-filtered session rows. Published in `0.1.12`. |
| Config/TOML preservation | Implemented | Root-partitioned Codex config passthrough keeps user settings, MCP servers, profiles, model defaults, approval/sandbox policy, and non-managed provider definitions. |
| Experimental Codex settings injection | Implemented | Defaults can be injected without treating user config as disposable. |
| Native Codex shim pass-through | Implemented | Admin/login/help/version paths bypass route election and exec native Codex. Public Homebrew remains binary-only and must not install the shim by default. |
| Home Manager lane | Implemented in source | Module defaults to binary-only install; managed `codex` shim is explicit opt-in. |
| Route-health recovery | Implemented | Transient provider degradation can recover after retry windows without becoming permanent auth death. Source after PR #279 also separates downstream client disconnects from upstream/provider failures so client `BrokenPipe` does not poison route health. |
| Redacted diagnostics and tracing | Implemented | JSON diagnostics and `OMUX_TRACE=1` support route/session/auth/runtime debugging without token, raw account id, session id, or path leakage. |
| Agent-safe reauth mediation | Contracted, partial surfaces | CLI JSON exposes consent/action fields and safe handoff-plan commands for upstream-owned login surfaces; future MCP tools must mirror CLI semantics. |
| Beta daemon | Experimental | Foreground tick engine and daemon-hosted beta may mediate status/handoffs; not a hidden dependency and not unmanaged hot-swap. |
| Claude adapter | Provider-proof only | `auth-status` and account-store isolation are the first proof lane; no Claude stay-afloat claim. |
| OMO, Pi, OpenCode, Kimi | Adapter-candidate only | Adjacent agent-control-plane proof does not equal oauth-mux keepalive support. |

## UX, DX, AX Stance

UX:

- The managed harness should feel like the upstream harness.
- Handoffs are labeled and user-mediated when upstream auth is required.
- A daemon beta may improve observation and mediation, but current Codex UX must
  not depend on a hidden background service.

DX:

- `just build`, `just test`, and `just check-local` remain the local development
  gates.
- `just release-proof <version>` is required before any registry mutation.
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

`0.1.12` is the current verified public release. It carries Codex 0.132 resume
authority parity for `logs_2.sqlite*` / `CODEX_SQLITE_HOME`, the #176
capture-review `--require-proxy-meta` gate, and PR #295's provider-namespace
resume picker fix. `just release-proof 0.1.12` passed before tag/release
mutation, and release workflow `26469045026` published GitHub Release
`v0.1.12` as non-draft/non-prerelease with 23 assets. The public Homebrew tap
is updated to `0.1.12`, `brew fetch --force jesssullivan/omux/oauth-mux`
passes, and the local Homebrew keg reports `0.1.12`. Lab PR #507 pins the Home
Manager source lane to the same release commit with `codexShim` disabled. npm
publication remains blocked/stale; npm `latest` still reports `0.1.9`.
Negative Codex cassettes, broader adapter proof, and daemon beta truth remain
follow-up work.
Windows managed-`codex` parity is intentionally assigned to the npm wrapper
lane rather than raw tarballs until a native Windows operator need is proven.
Future public install copy must avoid claiming a version or lane behavior until
that version is actually published and verified.

The release lanes remain:

- worktree dogfood;
- user-local dogfood;
- Nix package;
- npm;
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
| Wire cassette coverage | TIN-950 | #176 | PR #299 promoted a scrubbed current-release auth-failure fixture and replay smoke. Quota/rate-limit and all-fallbacks-exhausted cassette evidence is still needed before treating negative permutations as stable release proof. Linear currently marks TIN-950 Done while GitHub #176 remains open; reconcile only after real cassette acceptance or an explicit tracker correction. |
| Harness session authority bridge | TIN-979 / TIN-1624 | #191 / #288 | Closed for the original Codex bridge, with TIN-1624/#288 covering the Codex 0.132 `logs_2.sqlite*` / `CODEX_SQLITE_HOME` parity regression. Managed auth/config overlays bridge canonical session authority and root config while rejecting silent session-store import/copy. Future cross-harness authority work stays under #67/#68. |
| Codex session-store portability | TIN-936 | #161 | Policy is explicit: canonical bridge is supported; silent route-local session import/copy is rejected until a separate confirmed import command exists. |
| OTEL-friendly tracing | TIN-1148 | PR #225/#226 lineage | Implemented trace schema should become the standard support-bundle path. |
| Package parity and install lanes | TIN-1255 | #252 | `0.1.12` is published and verified across GitHub Release, Homebrew, curl installer assets, deb/rpm release assets, user-local dogfood, and lab Home Manager source pin; npm remains stale at `0.1.9`. |
| Home Manager and Windows shim parity | not assigned | #257 | Home Manager source lane is implemented with opt-in shim; Windows raw tarballs stay binary-only and npm is the managed-shim lane. |
| Provider proof beyond Codex | TIN-736 | #68 | Claude next; other agents stay adapter-candidate only. |
| Website truth refresh | TIN-734 / TIN-925 | external site repo | `omux.xoxd.ai` source lives outside this repo and must be refreshed from the ledger, QA matrix, and install-lane docs. |

## Acceptance Gates

- Local state refresh passes with current installed binary:
  `doctor`, `providers list`, `accounts list`, `route explain`,
  `codex preflight`, `broker-session-plan`, `stay-afloat next`,
  `status-latest`, and `daemon status`.
- Local validation passes: `zig build test`, targeted Codex smokes,
  `nix develop --command just check-local`, and the hybrid `nix flake check`
  package smoke.
- Dogfood process/memory concerns are backed by at least two redacted
  `dogfood-process-snapshot` artifacts before being called leaks.
- Public release validation passes: `just release-proof <version>`, release
  proof workflow, npm dry run/publish workflow as appropriate, Homebrew QA, and
  system package QA.
- Homebrew release validation proves both installed binary output and
  `brew info --json=v2` stable version semantics for the public tap formula.
- Public copy does not claim same-thread continuity, mid-turn recovery,
  unmanaged daemon hot-swap, non-Codex stay-afloat, universal provider support,
  or future package availability before publication.
