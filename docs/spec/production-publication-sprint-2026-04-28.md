# Production Publication Sprint

Date: 2026-04-28

Scope: move `oauth-mux` from internal alpha to a controlled public `v0.1.0`
publication path without adding daemon behavior or secret-bearing repository
state.

Issue context: Linear `TIN-491`, GitHub `tinyland-inc/lab#197`.

## Current Baseline

- `origin/main` contains the merged core mux, typed liveness, Codex three-account
  path, onboarding docs, live QA harness, registry dry-run scaffolding, and
  CI-only npm publish path.
- Hosted CI has passed Zig tests, Nix validation, and all six cross-compiles for
  the recent PR arc.
- The CI npm publish workflow has packed and dry-runed all seven generated
  tarballs. The stricter registry dry-run is now green after rotating the npm
  automation token: run `25029047263` passed `plan,github,npm,system` and
  dry-ran all seven npm tarballs.
- GloriousFlywheel cache-first proof is currently runner-gated; the most recent
  real proof predates the newest `main` commit.
- Hosted live-provider QA has workflow support for secret-scoped config,
  Codex CLI bootstrap, and a minimal hosted credential-store bundle. Run
  `25029923810` completed the Codex three-account matrix with
  `confirm=spend-real-calls`.

## Sprint Objective

Make the first public release boring:

1. every routine onboarding action is available from the installed binary;
2. every publication lane has a dry-run or documented deferral;
3. every spendful or secretful action is opt-in and secret-scoped;
4. release notes can explain known account states, rollback, and daemon limits;
5. the tag/publish sequence can be executed from CI without workstation secrets.

## Workstreams

### 1. Installed Onboarding Surface

Deliver `oauth-mux codex ...` commands for the Codex Max path:

- `oauth-mux codex bootstrap-dirs`
- `oauth-mux codex login <account>`
- `oauth-mux codex login-device <account>`
- `oauth-mux codex login-status [account]`
- `oauth-mux codex login-status-all`
- `oauth-mux codex onboard [--device|--status-only] [--accounts a,b,c]`
- `oauth-mux codex canary [--accounts a,b,c] [--capabilities c1,c2] [--live]`

The source-checkout `just codex-max-*` recipes should remain as aliases, not the
primary public interface.

Acceptance:

- `zig build test` passes.
- `just check` passes.
- Docs point public users at installed commands.

### 2. Secret-Scoped Live QA

Run hosted live QA only after the workflow has an encoded config secret and the
operator intentionally dispatches with `confirm=spend-real-calls`.

Known user-state target for Codex:

- two Codex Max subscription routes may be `live/quota_exhausted` until weekly
  limits refresh;
- the third account should remain available for API-backed usage;
- `quota_exhausted`, `rate_limited`, `degraded`, and `dead` must stay distinct
  typed outcomes.

Acceptance:

- hosted artifact captures typed liveness without printing token material;
- command-probe providers such as Codex install or otherwise expose their CLI
  before the probe step;
- dead credentials fail unless the run explicitly opts into negative testing;
- quota exhaustion is evidence, not a false CI infrastructure failure.

Credential materialization:

- `OMUX_LIVE_QA_CONFIG_B64` carries the mux config;
- `OMUX_LIVE_QA_STORE_TGZ_B64` carries a minimal `$HOME`-relative credential
  bundle, excluding caches and logs;
- the workflow rejects absolute paths and parent traversal before extraction.

Evidence:

- live QA `25029923810` installed `@openai/codex@0.125.0`, decoded the
  secret-scoped config and store bundle, and uploaded valid per-probe JSON plus
  redacted logs;
- `codex-mini`: `max-1`, `max-2`, and `max-3` all returned
  `live/available` with `decision=use_this`;
- `codex-max`: `max-1` and `max-2` returned `live/quota_exhausted` with
  `decision=try_next_account`; `max-3` returned `live/available` with
  `decision=use_this`.

### 3. Registry Dry-Runs

Use `.github/workflows/registry-dry-run.yml` for authenticated dry-runs from
CI. Start with `plan,github,npm,system`; add `homebrew` when a tap checkout is
available to the runner.

Acceptance:

- npm dry-run remains CI-only and provenance-capable;
- GitHub release auth check does not create a public release;
- system package metadata checks complete or record missing host tooling;
- rollback instructions stay linked from release notes.

Evidence:

- registry dry-run `25029047263` completed successfully on `main` with
  `plan,github,npm,system`;
- artifact `registry-dry-run-0.1.0` records GitHub auth OK, no existing
  `v0.1.0` release, all seven npm tarballs dry-run OK, and deb/rpm metadata OK.
- local release proof on this branch passed `just release-proof 0.1.0`,
  including Homebrew formula syntax, npm tarball packing, deb/rpm generation,
  curl installer smoke, and handoff regeneration;
- local Homebrew tap dry-run passed after updating the lane for Homebrew 5.1's
  tap/name audit path with `OMUX_HOMEBREW_TAP_NAME=tinyland-inc/tools`.

### 4. GloriousFlywheel Release Proof

Re-run the cache-first release proof after the `tinyland-nix` runner is healthy.
Do not claim this gate while jobs are only queued.

Acceptance:

- real GF job checks out the private action and completes
  `nix develop --command just release-proof-local 0.1.0`;
- if deferred, the release notes explicitly say which hosted and local gates
  substituted for it.

### 5. v0.1.0 Cut

Only after the gates above:

1. tag `v0.1.0`;
2. let release workflow attach artifacts;
3. review handoff and checksums;
4. run npm publish workflow first with `dry_run=true`, then with
   `dry_run=false`;
5. publish or defer Homebrew/deb/rpm/curl lanes according to dry-run evidence.

## Explicit Non-Goals

- no background daemon as a required product surface;
- no repository-stored token files or `.env`;
- no workstation npm publish;
- no ad hoc provider-specific hacks outside the provider schema unless a new
  transport/parser primitive is required.
