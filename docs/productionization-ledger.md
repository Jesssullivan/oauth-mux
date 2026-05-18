# Productionization Ledger

Updated: 2026-05-18

This ledger is the short operator map for oauth-mux productionization. It is
subordinate to the broker contract and Codex adapter contract, and it should be
refreshed when release truth, route evidence, or tracker state changes.

## Current Snapshot

- Repo state: `main` is clean against `origin/main` after the `0.1.7`
  package-parity refresh.
- CI state: GitHub Actions is the live source for the latest run. The
  2026-05-17 refresh verified the `v0.1.7` release workflow, npm publish
  workflow, and hosted system-package install QA.
- Version truth: public npm, GitHub Release, Homebrew, curl installer, and
  deb/rpm lanes resolve to `0.1.7`, but the 2026-05-18 shim investigation found
  a package-lane QA gap: public Homebrew `0.1.7` routes native admin commands
  such as `codex --version` through `oauth-mux codex`. GitHub Release `0.1.8`
  exists, but registry/tap publication is targeting source `0.1.9` after the
  Homebrew dry-run caught formula audit drift.
- Installed provenance: PATH can resolve a public package binary or a
  user-local dogfood binary depending on shell setup. Use `which -a oauth-mux`,
  `which -a codex`, `oauth-mux version --json`, and `codex preflight` before
  treating any installed-command run as release evidence.
- Homebrew truth: the public `jesssullivan/omux` tap installs `oauth-mux
  0.1.7`, includes a managed `codex` shim, and `brew info --json=v2`
  reports stable version `0.1.7`; the current public shim still needs the
  admin pass-through fix from this source tree.
- Codex route truth: refresh before every live test. The latest 2026-05-17
  22:24 EDT installed Homebrew `0.1.7` no-spend snapshot is `not_afloat`:
  all four named `codex-max` routes are runtime-ready and broker-ready but
  blocked as `unrecorded`. The next step is spend-confirmed route-health
  repair/probe, not managed resume.
- Latest local status truth: `oauth-mux codex status-latest --json` currently
  reports `brokered_without_fallback` from a rolling local artifact. This
  does not supersede the preserved quota-handoff proof; status artifacts must be
  refreshed before being used in public claims.
- Daemon truth: `oauth-mux daemon status --json` still reports
  `contract:"experimental_socket_stub"` and `hosts_stay_afloat:false`; any
  stale foreground tick snapshot is observational only. The beta daemon lane
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
| Route-health recovery | Implemented | Transient provider degradation can recover after retry windows without becoming permanent auth death. |
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

## Adapter Strategy

Codex remains the reference adapter until its negative/cassette matrix and
release truth are stable. Claude is the next likely adapter proof because it has
a narrow command-owned `auth-status` surface and account-store isolation to
validate. OMO, Pi, OpenCode, and Kimi should first get adapter contracts that
answer token shape, auth storage, reload boundary, quota signal, failure signal,
wire interception, process topology, and session authority. Until then, they may
consume oauth-mux diagnostics or future MCP repair prompts, but oauth-mux must
not claim to keep them alive.

## Release And Distribution Posture

`0.1.7` version availability is complete for the public install lanes, but
package parity is not complete until the shared Codex shim fix ships and the
package lanes prove native admin pass-through. Negative Codex cassettes,
broader adapter proof, and daemon beta truth remain follow-up work. Windows
managed-`codex` parity is intentionally assigned to the npm wrapper lane rather
than raw tarballs until a native Windows operator need is proven. Future public
install copy must avoid claiming a version or lane behavior until that version
is actually published and verified.

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
| Codex next-turn broker switch | TIN-916 | #131 | Managed Codex handoff is proven; keep remaining negative/permutation work distinct from same-thread or mid-turn claims. |
| Live Codex account-swap acceptance | TIN-951 | #177 | Done for managed Codex; strongest preserved proof is `docs/evidence/codex-engineered-quota-handoff-20260509/`. |
| Wire cassette coverage | TIN-950 | #176 | Needed before treating negative permutations as stable release proof. |
| Harness session authority bridge | TIN-979 | #191 | Implementation exists, but tracker should be reconciled against current bridge proof. |
| OTEL-friendly tracing | TIN-1148 | PR #225/#226 lineage | Implemented trace schema should become the standard support-bundle path. |
| Package parity and install lanes | TIN-1255 | #252 | `0.1.7` is published and verified across GitHub Release, npm, Homebrew, curl, and deb/rpm package lanes. |
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
- Public release validation passes: `just release-proof <version>`, release
  proof workflow, npm dry run/publish workflow as appropriate, Homebrew QA, and
  system package QA.
- Homebrew release validation proves both installed binary output and
  `brew info --json=v2` stable version semantics for the public tap formula.
- Public copy does not claim same-thread continuity, mid-turn recovery,
  unmanaged daemon hot-swap, non-Codex stay-afloat, universal provider support,
  or future package availability before publication.
