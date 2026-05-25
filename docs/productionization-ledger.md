# Productionization Ledger

Updated: 2026-05-25

This ledger is the short operator map for oauth-mux productionization. It is
subordinate to the broker contract and Codex adapter contract, and it should be
refreshed when release truth, route evidence, or tracker state changes.

## Current Snapshot

- Repo state: `main` matches `origin/main` at `42b103c`, including the
  BrokenPipe/client-disconnect hardening from PR #279 and the 0.1.10
  provenance/release preparation from PR #280.
- CI state: GitHub Actions is the live source for the latest run. Release
  workflow `26012676776`, registry dry-run `26012836911`, and npm publish
  `26013003383` verified the `v0.1.9` release lane on 2026-05-18. Any
  installed public `0.1.9` package predates PRs #260-#279 unless its binary hash
  is explicitly proven otherwise.
- Version truth: GitHub Release, curl installer assets, deb/rpm assets, and the
  public Homebrew tap resolve to `0.1.10`; this was rechecked on 2026-05-25.
  npm `latest` is still `0.1.9` because the CI npm lane currently lacks usable
  npm auth and fails `npm whoami` with 401. The 2026-05-18/19 shim
  investigation fixed a package-lane ownership bug: the Homebrew formula must
  not install or link a managed `codex` shim by default.
- Installed provenance: PATH may resolve Homebrew before user-local dogfood.
  Use `which -a oauth-mux`, `which -a codex`, `oauth-mux version --json`, and
  `codex preflight` before treating any installed-command run as release
  evidence. `version --json` must be checked for both binary SHA-256 and
  `runtime_identity.build_id`; source builds after this update report a git
  describe-style build id, while tagged releases report the exact tag such as
  `v0.1.10`.
- Homebrew truth: the public `jesssullivan/omux` tap advertises `oauth-mux
  0.1.10` and the local linked keg is `0.1.10`. Homebrew is a binary-only
  package lane by default: QA must prove
  `brew install jesssullivan/omux/oauth-mux` installs `oauth-mux`, does not
  install an `OMUX_CODEX_SHIM`, and leaves native `codex` command resolution
  unchanged. The formula must declare explicit version metadata because Linux
  Homebrew can infer `64-linux` from the x86_64 Linux tarball name.
- Codex route truth: the 2026-05-21 02:57 UTC post-repair no-spend refresh used
  user-local `oauth-mux 0.1.9`. All four named `codex-max` route stores are
  runtime-ready and broker-ready. `codex:max-3#codex-max` is selected and
  selectable; `max-4` is a live selectable fallback; `max-1` and `max-2` remain
  blocked as `unrecorded`. Current state is `session_start_ready:true`,
  `fallback_ready:true`, `single_route_at_risk:false`. The next live cassette
  run still needs a just-in-time no-spend refresh plus explicit operator
  approval for provider-spend capture.
- Latest local status truth: `oauth-mux codex status-latest --json` currently
  reports `brokered_without_fallback` from a rolling local artifact. This is
  stale relative to current route truth and does not supersede the preserved
  quota-handoff proof; status artifacts must be refreshed before being used in
  public claims.
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
| Session authority bridge | Implemented | Managed auth/config overlays bridge canonical Codex session authority, including `state_5.sqlite*` when present. |
| Config/TOML preservation | Implemented | Root-partitioned Codex config passthrough keeps user settings, MCP servers, profiles, model defaults, approval/sandbox policy, and non-managed provider definitions. |
| Experimental Codex settings injection | Implemented | Defaults can be injected without treating user config as disposable. |
| Native Codex shim pass-through | Implemented in source, release pending | Admin/login/help/version paths bypass route election and exec native Codex. The 2026-05-18 package-lane fix must ship before public Homebrew/curl claims use this as installed truth. |
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

- Agents use no-spend inspection surfaces first: `discover`, `providers list`,
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
regression fix is landed in source; the immediate operational risk is stale
installed package/dogfood provenance. Next work should prioritize installed
build-id proof, package parity/release hygiene, no-spend route/process truth
refresh, real Codex wire cassettes, tracker reconciliation, then later sidecar
and non-Codex provider work.

## Release And Distribution Posture

`0.1.10` version availability is complete for GitHub Release, curl installer,
deb/rpm assets, and Homebrew as of 2026-05-25: GitHub Release `v0.1.10` is
published and non-draft, Homebrew stable/linked keg is `0.1.10`, and hosted
system package install QA passed for the published `.deb` / `.rpm` assets. npm
publication remains blocked on npm auth; npm `latest` still reports `0.1.9`.
Negative Codex
cassettes, broader adapter proof, and daemon beta truth remain follow-up work.
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
| Wire cassette coverage | TIN-950 | #176 | Still needed before treating negative permutations as stable release proof. Linear currently marks TIN-950 Done while GitHub #176 remains open; reconcile only after real cassette acceptance or an explicit tracker correction. |
| Harness session authority bridge | TIN-979 | #191 | Closed for Codex: managed auth/config overlays bridge canonical session authority, `state_5.sqlite*`, and root config while rejecting silent session-store import/copy. Future cross-harness authority work stays under #67/#68. |
| Codex session-store portability | TIN-936 | #161 | Policy is explicit: canonical bridge is supported; silent route-local session import/copy is rejected until a separate confirmed import command exists. |
| OTEL-friendly tracing | TIN-1148 | PR #225/#226 lineage | Implemented trace schema should become the standard support-bundle path. |
| Package parity and install lanes | TIN-1255 | #252 | `0.1.9` is published and verified across GitHub Release, npm, Homebrew, curl installer assets, and deb/rpm release assets. |
| Home Manager and Windows shim parity | not assigned | #257 | Home Manager source lane is implemented with opt-in shim; Windows raw tarballs stay binary-only and npm is the managed-shim lane. |
| Provider proof beyond Codex | TIN-736 | #68 | Claude next; other agents stay adapter-candidate only. |
| Website truth refresh | TIN-734 / TIN-925 | external site repo | `omux.xoxd.ai` source lives outside this repo and must be refreshed from the ledger, QA matrix, and install-lane docs. |

## Acceptance Gates

- No-spend state refresh passes with current installed binary:
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
