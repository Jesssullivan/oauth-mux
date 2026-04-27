# oauth-mux Development Timeline

Updated: 2026-04-27

Issue context: Linear `TIN-491`, GitHub `tinyland-inc/lab#197`.

## Current Stage

`oauth-mux` is in internal alpha: the core mux, typed liveness model, provider
schema, Codex Max operator flow, release staging, and no-secret E2E proof are
implemented. It is ready for controlled operator use and PR review, but not yet
for public unattended production use.

The remaining production gap is no longer the core selection model. The gap is
operational hardening: live-provider QA, authenticated package publication dry
runs, documented rollback, and real GloriousFlywheel private-action proof once
`GF_ACTIONS_TOKEN` is configured.

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
  Present but token-gated. A green skip is useful diagnostic evidence, not a
  cache-first proof. Count it only when the private action checks out and runs.

## Production Readiness

Ready now:

- internal operator experimentation;
- local three-account Codex Max setup and explicit probe runs;
- schema-only provider authoring against no-secret fixtures;
- draft release artifact review;
- PR review with hosted CI evidence.

Not ready yet:

- unattended automatic live-provider probing;
- public npm/Homebrew/deb/rpm publication;
- required self-hosted release gate;
- background daemon token refresh as an operational dependency;
- documented rollback for each registry lane;
- formal security review of secret backends and generated config dirs.

## Next Arc

1. Add a live-provider QA workflow that is manual-only, secret-scoped, and
   budget-aware. It should run `codex-mini` first, then higher-cost routes only
   when explicitly requested.

2. Convert the release handoff into authenticated dry-run lanes:
   npm provenance dry run, Homebrew formula audit in the tap, and deb/rpm
   repository staging checks.

3. Configure `GF_ACTIONS_TOKEN` or otherwise expose the private
   GloriousFlywheel action so cache-first CI can prove the same E2E gate on
   `tinyland-nix`.

4. Add a small canary script for the three real Codex Max accounts that reports
   liveness and route decisions without changing auth state or leaking tokens.

5. Decide the daemon boundary: keep it optional until token refresh semantics
   and provider-specific refresh safety are proven for each OAuth-backed
   harness.
