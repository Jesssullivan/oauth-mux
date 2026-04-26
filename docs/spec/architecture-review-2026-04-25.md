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
- Release packaging templates exist for curl installer, npm, Homebrew, and
  nfpm; checksum/artifact publication remains release-automation work.
- The live Codex route probes intentionally spend small subscription calls and
  should remain explicit operator actions or bounded fallback checks, not a
  background polling loop.
- Canonical `just check` passes through one Nix shell entry. Direct
  `zig build test` / `zig build` remains faster for tight local iteration, but
  `just check` is still the operator-facing validation command.

## Next Arc

1. Add provider-specific MCP examples only when the resource server URL and
   token audience are explicit.
2. Turn the existing dist templates into a release automation path that emits
   tarballs, checksums, npm platform packages, Homebrew formula updates, and
   nfpm deb/rpm artifacts from one version input.
3. Update TIN-491 and GitHub issue #197 with this checkpoint and the remaining
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
codex-max: max-1, max-2, max-3 -> 200/use_this/live/available
```
