# OAuth Mux Architecture Review

Updated: 2026-04-26

Issue context: Linear `TIN-491`, GitHub `tinyland-inc/lab#197`.

## Current Checkpoint

This checkpoint turns `oauth-mux` from a simple account switcher into a typed,
schema-driven OAuth routing core.

Implemented:

- Versioned typed health persistence for account and route liveness.
- Distinct auth, operability, and availability states:
  `live`, `degraded`, and `dead`.
- Account health keys and route health keys:
  `provider:account` and `provider:account#capability`.
- Provider-level fallback for provider-wide degradation.
- Capability-aware selection via profile entries and `--capability`.
- Declarative provider definitions for token parsing, env/config injection,
  refresh endpoints, failure classification, and capability probes.
- Semantic `config validate` for provider definitions, profile references,
  secrets, direct env mappings, failure rules, and probe definitions.
- Std-only probe execution module that classifies HTTP and command probe
  results and records them into typed health state.
- Operator-facing `probe` command for account validation and capability probes
  without launching a target command.
- Codex Max example config and operator plan for three subscription accounts.
- `init --codex-max` for generating the three-account scaffold directly.
- Persisted last-probe evidence fields: source, observed time, retry-after,
  hint class, and mux decision.
- Live validation of three isolated Codex Max stores, each logged in through
  Codex CLI with its own `CODEX_HOME`.
- Live command-probe validation for both semantic Codex route labels:
  `codex-mini` and `codex-max`.
- Induced route-failure pipeline coverage: a degraded `codex-max` route falls
  through to the next account while the same account remains eligible for
  `codex-mini`.
- Provider authoring checklist for schema-only OAuth harness support, including
  HTTP-vs-command probe admission rules and the current Codex direct-HTTP
  research finding.
- Probe privacy validation in `config validate`: capability probe URLs and
  command argv entries may not embed token material.
- Failure-rule coverage validation in `config validate`: probed schema
  providers must define failure rules, and each failure rule must include a
  concrete matcher rather than acting as a catch-all classifier.
- Fixture redaction validation in `zig build test`: files under
  `test/fixtures` are scanned for common OAuth token, bearer header, cookie,
  and API-key markers.
- Explicit Codex direct-HTTP probe decision record: no direct Codex HTTP probe
  is admitted until an official/provider-owned source documents endpoint
  semantics, token audience, typed failure classes, reset behavior, and quota
  impact.
- `just check` now enters `nix develop` once and runs both `zig build test` and
  `zig build` inside that shell, avoiding duplicate Nix wrapper startup.
- Provider probe admission matrix for Codex, Claude, Anthropic API, MCP,
  GitHub, Linear, Figma, Vercel, and FlakeHub.
- Built-in GitHub `identity` capability probe using the documented
  `GET /user` endpoint, with GitHub-specific 403 rate-limit vs degraded
  classification and an env-backed example config.
- Narrow HTTP probe body support for GraphQL identity checks, plus built-in
  Linear `identity` capability probing `viewer` through the documented GraphQL
  endpoint.
- Built-in Vercel `identity` capability probe using the documented `GET /v2/user`
  endpoint, with a scoped env-backed example config.
- Built-in Figma REST OAuth `identity` capability probe using the documented
  `GET /v1/me` endpoint.
- Generic custom-token-header probe auth (`auth = token_header`) plus Figma
  PAT `identity-pat` support using `X-Figma-Token`. Plan access tokens are not
  mapped to `/v1/me` because Figma excludes that endpoint for plan tokens.
- URL-template expansion for non-secret resource identifiers in probe URLs,
  plus Figma plan-token `file-metadata-plan` support using
  `GET /v1/files/{{OMUX_FIGMA_PLAN_FILE_KEY}}/meta`.
- Built-in Claude Code `auth-status` command probe using the documented
  `claude auth status --json` command under the selected `CLAUDE_CONFIG_DIR`.
- Built-in FlakeHub / Determinate `status` command probe using
  `determinate-nixd status`; direct HTTP remains unadmitted.
- Built-in MCP HTTP `resource-metadata` and `resource` probe templates for
  RFC 9728 protected resource metadata and audience-bound bearer resource
  checks.
- Release entrypoint alignment: `just release` now aliases the full release
  build, Windows targets are included in `release-all`, and `just check`
  validates every example config after build.
- GloriousFlywheel substrate integration plan and first CI lace-up:
  `just check` now delegates to devshell-local `just check-local`, CI has a
  `tinyland-nix` cache-first lane through the GloriousFlywheel `nix-job`
  action, `just release` runs the single Zig release graph, and CI/release
  matrices include all six documented targets. See
  `docs/spec/gloriousflywheel-substrate-integration-2026-04-26.md`.
- Local release staging: `just release-local <version>` emits six binary
  tarballs, checksums, a rendered Homebrew formula, npm package workspace and
  tarballs, a checksum-verifying curl installer, plus nfpm configs and deb/rpm
  artifacts through the Nix dev shell.
- Local release proof: `just release-proof <version>` stages the release and
  smoke-checks required artifacts, checksums, archive payloads, Homebrew
  rendering, local npm installation, local installer execution, and
  non-publishing release handoff generation.
- Release handoff proof: `just release-handoff <version>` validates an already
  staged tree and writes `handoff/release-handoff.md`,
  `handoff/publish-files.txt`, and `handoff/SHA256SUMS.full` with GitHub
  Release attachments, npm publish order, Homebrew tap input, deb/rpm files,
  and full checksums.
- Deterministic local E2E proof: `just e2e` creates a temporary provider
  definition, command probe, config, and state directory to prove env
  injection, command probes, route-scoped quota fallback, health persistence,
  and `exec` target injection without contacting live OAuth providers.
- Manual GloriousFlywheel release proof: `.github/workflows/release-proof.yml`
  runs the same proof through the private cache-first `nix-job` action on
  `tinyland-nix` when runner capacity and `GF_ACTIONS_TOKEN` are available.
- Tag release publication now runs the same Nix-backed release proof before
  uploading staged artifacts to GitHub Releases.
- Root README and release runbook covering local validation, release staging,
  GitHub release behavior, and the GloriousFlywheel runner/token boundary.

## Key Decisions

### Route Health Does Not Poison Account Health

Quota exhaustion for `codex:max-1#codex-max` must not mark
`codex:max-1` unusable for every route. Account-level auth failures still
dominate every route on that account.

### Provider Definitions Stay Data-First

New AI harness support should usually be added as config data:

- credential JSON paths
- refresh endpoints
- config directory or env injection shape
- failure classification rules
- optional capability probe plans

Compiled adapters remain reserved for behavior that cannot be represented
safely with small data structures.

### Probe Plans Are Not Secrets

Provider definitions may describe how to probe a capability. The access token is
injected only at execution time, never persisted in the provider schema, health
state, or logs.

Command probes follow the same rule: the provider definition stores argv only,
and the pipeline supplies account-scoped env such as `CODEX_HOME` at execution
time.

### Codex Max Needs Capability Routes

Three Codex Max accounts are not just three login stores. The mux must know
whether a specific model/task route is unavailable, quota exhausted, temporarily
rate-limited, or auth-dead.

### Codex Uses Command Probes First

The first verified Codex route probes use `codex exec --json` rather than a
direct OAuth resource endpoint. That matches the subscription-backed ChatGPT
surface actually exposed by Codex CLI 0.125.0 on this workstation and lets the
mux distinguish a live route from plan/model incompatibility by parsing JSONL
events.

### Direct Codex HTTP Probes Are Unadmitted

As of 2026-04-26, no official Codex subscription-account HTTP health endpoint
has been found with documented method, request shape, token audience, response
schema, typed failure classes, retry/reset semantics, and quota impact. Treat
direct Codex HTTP probing as blocked until that admission gate is satisfied.

Decision record:
`docs/spec/codex-direct-http-probe-decision-2026-04-26.md`.

## Current Risks

- Direct Codex HTTP probing is intentionally unadmitted pending official
  endpoint documentation. MCP probes are now resource-server templates; live
  use still requires an explicit resource metadata URL or resource probe URL.
- Probe execution is intentionally minimal: HTTP method, URL, bearer auth,
  explicit custom token headers, success range, retry-after, one hint header,
  one optional response-body hint, or argv plus account env and an explicit
  timeout. Request body templating and richer header extraction are future work.
- Health persistence is versioned and backward-compatible, but migration policy
  beyond the current evidence fields is not yet documented.
- Release packaging now has a local staging, smoke-proof, and non-publishing
  handoff command. GitHub release publication uses that proof before attaching
  artifacts, but real npm/Homebrew/deb/rpm registry publication is still future
  work.
- The deterministic E2E harness proves the mux core without live credentials,
  but it is not a substitute for bounded live-provider QA. Codex, Claude,
  GitHub, Linear, Figma, Vercel, FlakeHub, and MCP live probes still need
  explicit secret scoping and call budgets.
- GloriousFlywheel cache-first CI proves shared Nix/Attic substrate attachment,
  not universal remote execution or Bazel remote-cache behavior. `oauth-mux`
  remains Zig-only, so Bazel should stay out until there is a real target graph.
- `GloriousFlywheel` is a private repo, so the cache-first CI lane requires
  `GF_ACTIONS_TOKEN` to check out the composite action locally. This is now
  configured for `oauth-mux`; PR run `25009779392`, job `73266579091`, checked
  out the private action and ran `nix develop --command just check-local` on
  `tinyland-nix`. Without that secret, CI records the skipped proof instead of
  claiming substrate execution.
- The live Codex route probes intentionally spend small subscription calls and
  should remain explicit operator actions or bounded fallback checks, not a
  background polling loop.
- Canonical `just check` passes through one Nix shell entry. Direct
  `zig build test` / `zig build` remains faster for tight local iteration, but
  `just check` is still the operator-facing validation command.

## Next Arc

1. Add provider-specific MCP examples only when the resource server URL and
   token audience are explicit.
2. Add a bounded live-provider QA lane that consumes real calls only when
   explicitly triggered with scoped secrets.
3. Turn the generated registry handoff into authenticated dry-run lanes for npm,
   Homebrew tap updates, and deb/rpm repositories.
4. Promote the manual GloriousFlywheel release proof into a required
   pre-publication self-hosted gate once runner capacity is stable enough for
   release blocking.
5. Update TIN-491 and GitHub issue #197 with this checkpoint and the remaining
   provider-verification work.

## Validation

Latest validation at this checkpoint:

```text
zig build test
passed

zig build
passed

OMUX_CONFIG=$PWD/examples/codex-max.config.json ./zig-out/bin/oauth-mux config validate
config: valid

OMUX_CONFIG=$PWD/examples/github.config.json ./zig-out/bin/oauth-mux config validate
config: valid

OMUX_CONFIG=$PWD/examples/linear.config.json ./zig-out/bin/oauth-mux config validate
config: valid

OMUX_CONFIG=$PWD/examples/vercel.config.json ./zig-out/bin/oauth-mux config validate
config: valid

OMUX_CONFIG=$PWD/examples/figma.config.json ./zig-out/bin/oauth-mux config validate
config: valid

OMUX_CONFIG=$PWD/examples/figma-pat.config.json ./zig-out/bin/oauth-mux config validate
config: valid

OMUX_CONFIG=$PWD/examples/figma-plan.config.json ./zig-out/bin/oauth-mux config validate
config: valid

OMUX_CONFIG=$PWD/examples/claude.config.json ./zig-out/bin/oauth-mux config validate
config: valid

OMUX_CONFIG=$PWD/examples/flakehub.config.json ./zig-out/bin/oauth-mux config validate
config: valid

OMUX_CONFIG=$PWD/examples/mcp-http.config.json ./zig-out/bin/oauth-mux config validate
config: valid

just check
validates every examples/*.config.json and prints all checks passed

just codex-max-login-status-all
max-1 -> Logged in using ChatGPT
max-2 -> Logged in using ChatGPT
max-3 -> Logged in using ChatGPT

just codex-max-probe-all
codex-mini: max-1, max-2, max-3 -> 200/use_this/live/available

just codex-max-probe-all codex-max
current review refresh:
max-1#codex-max -> degraded/unknown_4xx/status 400
max-2#codex-max -> degraded/unknown_4xx/status 400
profile-level codex-max fallback -> selected max-3#codex-max with 200/use_this/live/available

just release
single Zig release graph builds all six documented targets

just release-local 0.1.0
emits six binary tarballs, SHA256SUMS, Homebrew formula, npm package workspace,
npm tarballs, nfpm configs, and deb/rpm output

just release-proof 0.1.0
stages the release and verifies required artifacts, checksums, archive payloads,
Homebrew rendering, local npm installation, and installer execution
```
