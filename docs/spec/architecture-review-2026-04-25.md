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

## Current Risks

- Direct provider probe endpoints are not yet pinned for Codex/Claude/MCP. The
  schema can express HTTP and command probes, but direct HTTP endpoint semantics
  still need provider verification.
- Probe execution is intentionally minimal: HTTP method, URL, bearer auth,
  success range, retry-after, one hint header, or argv plus account env and an
  explicit timeout. Request body templating and richer header extraction are
  future work.
- Health persistence is versioned and backward-compatible, but migration policy
  beyond the current evidence fields is not yet documented.
- No release packaging changes have been made in this checkpoint.
- The live Codex route probes intentionally spend small subscription calls and
  should remain explicit operator actions or bounded fallback checks, not a
  background polling loop.

## Next Arc

1. Add live provider verification for the first safe non-quota-burning Codex
   HTTP status endpoint, if one exists.
2. Promote the remaining provider authoring checks into config/test affordances
   where useful, starting with fixture redaction.
3. Update TIN-491 and GitHub issue #197 with this checkpoint and the remaining
   provider-verification work.

## Validation

Latest validation at this checkpoint:

```text
just check
all checks passed

just codex-max-login-status-all
max-1 -> Logged in using ChatGPT
max-2 -> Logged in using ChatGPT
max-3 -> Logged in using ChatGPT

just codex-max-probe-all
codex-mini: max-1, max-2, max-3 -> 200/use_this/live/available

just codex-max-probe-all codex-max
codex-max: max-1, max-2, max-3 -> 200/use_this/live/available
```
