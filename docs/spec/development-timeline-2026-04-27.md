# oauth-mux Development Timeline

Updated: 2026-04-28

Issue context: Linear `TIN-491`, GitHub `tinyland-inc/lab#197`.

## Current Stage

`oauth-mux` is in internal alpha: the core mux, typed liveness model, provider
schema, Codex Max operator flow, release staging, and no-secret E2E proof are
implemented. It is ready for controlled operator use and PR review, but not yet
for public unattended production use.

The remaining production gap is no longer the core selection model. The gap is
operational hardening: live-provider QA execution with real secrets,
authenticated package publication dry-runs, rollback rehearsal, and
post-merge GloriousFlywheel release-proof execution before public tags.

The current Codex operator state is the expected subscription permutation:
two Codex Max routes are waiting on weekly-limit refresh and should classify as
route-scoped `live/quota_exhausted`, while a third account remains active for
API-backed usage. That is represented as route availability, not generic
degradation or auth death.

## Completed Arc

1. Research and formal model.
   OAuth/MCP governance notes, provider admission rules, liveness algebra, and
   route-scoped fallback semantics are documented.

2. Core mux implementation.
   The Zig pipeline handles provider resolution, account selection, secret
   reads, token parsing, typed health, env/config injection, and exec handoff.

3. Provider schema and probes.
   Built-ins now cover Codex, Claude, GitHub, Linear, Vercel, Figma, FlakeHub,
   and MCP HTTP resource-server probes. New providers can usually be added as
   JSON provider definitions rather than compiled code.

4. Codex Max operator path.
   Three isolated `CODEX_HOME` accounts are modeled as named accounts with
   separate capability routes for `codex-mini` and `codex-max`.

5. Release substrate.
   `just release-proof <version>` stages six targets, verifies checksums,
   tests the npm shim and curl installer locally, and writes the registry
   handoff without using publication credentials.

6. Deterministic E2E.
   `just e2e` creates a temporary provider and proves config validation, env
   injection, command probes, route-scoped quota fallback, persisted health,
   and `exec` injection without live credentials or network calls.

7. Onboarding and discovery surface.
   `oauth-mux discover --json`, `oauth-mux codex onboard`,
   `oauth-mux codex canary`, `docs/onboarding.md`, manual live-provider QA,
   registry dry-run, rollback, and daemon-boundary runbooks now define the
   operator and agent path. Source-checkout `just codex-max-*` recipes are thin
   aliases over the installed CLI surface.

## Current Gates

- `just check`
  Runs unit tests, build, example config validation, and no-secret E2E.

- Hosted PR CI
  Runs direct Zig build/test, example validation, no-secret E2E, release build,
  and all six cross-compiles.

- `just release-proof <version>`
  Runs local release staging, artifact smoke checks, installer proof, npm shim
  proof, and handoff generation.

- GloriousFlywheel cache-first lane
  Proven on PR run `25009779392`, job `73266579091`: the private
  `GloriousFlywheel` action checked out, `nix-job` ran on `tinyland-nix`, and
  `nix develop --command just check-local` passed. Cache push is intentionally
  disabled on PR events.

- Manual productization lanes
  `scripts/live-provider-qa.sh` and `.github/workflows/live-provider-qa.yml`
  require `spend-real-calls`; `scripts/registry-dry-run.sh` and
  `.github/workflows/registry-dry-run.yml` require `registry-dry-run`.

- CI-only npm publication
  `.github/workflows/npm-publish.yml` publishes only generated release
  tarballs, with npm provenance, after `just release-proof-local <version>`.
  Auth can come from Actions secrets, token files, or SOPS at runtime; token
  material is never committed or printed.

- Codex canary and secret-scoped live QA
  `oauth-mux codex canary` captures no-spend config/discovery/status/health and
  per-account `codex login status` evidence, then delegates to live probes only
  when `--live` is explicitly supplied.

- Secret-scoped Codex live QA
  The target hosted run should classify `max-1#codex-max` and
  `max-2#codex-max` as `live/quota_exhausted` with reset evidence, while
  keeping the third account available for fallback/API-backed usage. The QA
  script treats typed quota/rate/degraded outcomes as valid evidence unless
  `OMUX_LIVE_QA_REQUIRE_AVAILABLE=1` is set.

## Production Readiness

Ready now:

- internal operator experimentation;
- local three-account Codex Max setup and explicit probe runs;
- schema-only provider authoring against no-secret fixtures;
- draft release artifact review;
- PR review with hosted CI evidence.

Not ready yet:

- unattended automatic live-provider probing;
- public Homebrew/deb/rpm publication;
- required self-hosted release gate;
- background daemon token refresh as an operational dependency;
- formal security review of secret backends and generated config dirs.

## Next Arc

1. Run the live-provider QA workflow with scoped secrets from `main` so the
   hosted artifact path proves the same Codex matrix that has now passed
   locally.

2. Run authenticated registry dry-run lanes:
   npm dry run, Homebrew formula audit in the tap, GitHub release auth check,
   and deb/rpm metadata checks.

3. After merge, run the manual GloriousFlywheel release-proof workflow from
   `main` before publishing tags. GitHub cannot dispatch PR-local workflow
   files until they exist on the default branch.

4. Revisit the daemon boundary only after live-provider QA covers refresh,
   timeout, quota, and provider-owned CLI session behavior.
