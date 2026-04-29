# oauth-mux Development Timeline

Updated: 2026-04-28

Issue context: Linear `TIN-491`, GitHub `tinyland-inc/lab#197`.

## Current Stage

`oauth-mux` is now published as a controlled public tool for the first concrete
use case. `v0.1.2` is the first usable public npm release, the Codex
three-account path is live-proven through hosted secret-scoped QA, and the full
registry dry-run path has passed for the current release.

The remaining product gap is no longer core selection or publication mechanics.
The gap is adoption: first-run clarity, website narrative, provider-author
contribution paths, community feedback, and precise provider-support language.

The current Codex operator state is that all three configured Codex accounts are
active and classify as `live.available` for both `codex-mini` and `codex-max`.
Earlier quota-exhaustion permutations remain valuable fixture and QA scenarios:
they should continue to classify as route-scoped availability, not generic
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

8. Public package and registry proof.
   `v0.1.2` is published on npm, the orphaned partial `0.1.1` platform packages
   are deprecated through CI, and registry dry-run lanes now treat
   already-published package versions as valid only after registry
   confirmation.

9. Current adoption planning.
   `docs/spec/product-adoption-sprint-2026-04-28.md` defines the website,
   launch, outreach, and `v0.1.3` onboarding arc.

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
  tarballs after `just release-proof-local <version>`. npm provenance stays
  enabled for public source repositories and can be explicitly disabled for a
  private-source release. Auth can come from Actions secrets, token files, or
  SOPS at runtime; token material is never committed or printed.

- Codex canary and secret-scoped live QA
  `oauth-mux codex canary` captures no-spend config/discovery/status/health and
  per-account `codex login status` evidence, then delegates to live probes only
  when `--live` is explicitly supplied.

- Secret-scoped Codex live QA
  The latest hosted run on `main` classifies all three Codex accounts as
  `live.available` for both `codex-mini` and `codex-max`. The QA script still
  treats typed quota/rate/degraded outcomes as valid evidence unless
  `OMUX_LIVE_QA_REQUIRE_AVAILABLE=1` is set, so future quota-reset permutations
  remain modeled without turning into infrastructure failures.

## Product Readiness

Ready now:

- internal operator experimentation;
- local three-account Codex Max setup and explicit probe runs;
- schema-only provider authoring against no-secret fixtures;
- public npm install of `v0.1.2`;
- hosted live QA for the Codex account matrix;
- release artifact review and registry dry-runs;
- PR review with hosted CI and GloriousFlywheel evidence.

Not ready yet:

- unattended automatic live-provider probing;
- broad public claims that every provider is live-proven;
- public Homebrew/deb/rpm publication mutation;
- background daemon token refresh as an operational dependency;
- formal security review of secret backends and generated config dirs;
- website and launch surfaces.

## Next Arc

1. Land the product adoption sprint plan and split `TIN-491` into focused
   follow-up Linear tickets.

2. Implement `v0.1.3` onboarding improvements: `doctor`, redacted report bundle,
   friendlier setup aliases, and provider status listing.

3. Build the website around installed CLI flows, typed liveness, redacted JSON,
   and the provider support matrix.

4. Rerun hosted live QA and registry dry-run lanes for the next version before
   CI-only publication.

5. Revisit the daemon boundary only after live-provider QA covers refresh,
   timeout, quota, and provider-owned CLI session behavior.
