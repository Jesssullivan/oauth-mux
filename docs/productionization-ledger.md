# Productionization Ledger

Updated: 2026-05-16

This ledger is the short operator map for oauth-mux productionization. It is
subordinate to the broker contract and Codex adapter contract, and it should be
refreshed when release truth, route evidence, or tracker state changes.

## Current Snapshot

- Repo state: `main` is clean against `origin/main`; no open GitHub PRs were
  present in the 2026-05-16 refresh.
- CI state: the latest checked `main` CI runs were green through run
  `25930367658`.
- Version truth: local/source dogfood is `0.1.7`; public npm, GitHub Release,
  and Homebrew remain `0.1.6`.
- Installed dogfood: active `oauth-mux` resolves to the user-local binary and
  active `codex` resolves to the oauth-mux-managed shim; native Codex is still
  discoverable for pass-through.
- Codex route truth: `codex-max` currently has four selectable broker-ready
  routes, `session_start_ready:true`, `fallback_ready:true`, and
  `single_route_at_risk:false`.
- Latest local status truth: `oauth-mux codex status-latest --json` currently
  reports `successful_live_quota_handoff`; status artifacts are rolling local
  evidence and must be refreshed before being used in public claims.
- Daemon truth: `oauth-mux daemon status --json` still reports
  `contract:"experimental_socket_stub"`; the beta daemon lane must host the
  same foreground tick engine and must not claim unmanaged hot-swap.

## Feature Ledger

| Feature | Current level | Notes |
| --- | --- | --- |
| Managed Codex launch/resume | Live-proven | Reference adapter path for `oauth-mux codex` and `oauth-mux codex resume`. |
| Codex quota handoff | Live-proven for managed Codex | Strongest preserved proof lives in `docs/evidence/codex-engineered-quota-handoff-20260509/`. |
| Session authority bridge | Implemented | Managed auth/config overlays bridge canonical Codex session authority, including `state_5.sqlite*` when present. |
| Config/TOML preservation | Implemented | Root-partitioned Codex config passthrough keeps user settings, MCP servers, profiles, model defaults, approval/sandbox policy, and non-managed provider definitions. |
| Experimental Codex settings injection | Implemented | Defaults can be injected without treating user config as disposable. |
| Native Codex shim pass-through | Implemented | Admin/login/help/version paths bypass route election and exec native Codex. |
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

Hold `0.1.7` as a release candidate until the truth docs, tracker state,
negative cassettes, and daemon beta boundary are current. Public install copy
must continue to say `0.1.6` until npm, GitHub Release, and Homebrew are
actually published and verified.

The release lanes remain:

- worktree dogfood;
- user-local dogfood;
- Nix package;
- GitHub Release tarballs and installer;
- npm;
- Homebrew;
- deb/rpm packages.

Remote/browser validation should use the repo's remote execution lane when a
browser is needed; local Playwright is not part of this CLI proof path.

## Tracker Map

| Theme | Linear | GitHub | Current stance |
| --- | --- | --- | --- |
| Broker daemon and adapter contract | TIN-738 | #67 | Anchor remains open until daemon beta and second-adapter validation are honest. |
| Codex next-turn broker switch | TIN-916 | #131 | Codex is the reference path; keep evidence distinct from same-thread or mid-turn claims. |
| Live Codex account-swap acceptance | TIN-951 | #177 | Spend-confirmed only; requires selected route plus spare fallback and redacted artifacts. |
| Wire cassette coverage | TIN-950 | #176 | Needed before treating negative permutations as stable release proof. |
| Harness session authority bridge | TIN-979 | #191 | Implementation exists, but tracker should be reconciled against current bridge proof. |
| OTEL-friendly tracing | TIN-1148 | PR #225/#226 lineage | Implemented trace schema should become the standard support-bundle path. |
| Provider proof beyond Codex | TIN-736 | #68 | Claude next; other agents stay adapter-candidate only. |

## Acceptance Gates

- No-spend state refresh passes with current installed binary:
  `doctor`, `providers list`, `accounts list`, `route explain`,
  `codex preflight`, `broker-session-plan`, `stay-afloat next`,
  `status-latest`, and `daemon status`.
- Local validation passes: `zig build test`, targeted Codex smokes, and
  `nix develop --command just check-local`.
- Public release validation passes: `just release-proof <version>`, release
  proof workflow, npm dry run/publish workflow as appropriate, Homebrew QA, and
  system package QA.
- Public copy does not claim same-thread continuity, mid-turn recovery,
  unmanaged daemon hot-swap, non-Codex stay-afloat, universal provider support,
  or public `0.1.7` availability before publication.
