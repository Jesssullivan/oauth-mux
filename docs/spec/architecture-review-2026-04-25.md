# OAuth Mux Architecture Review

Updated: 2026-04-25

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
- Std-only probe execution module that classifies probe HTTP results and records
  them into typed health state.
- Operator-facing `probe` command for account validation and capability probes
  without launching a target command.
- Codex Max example config and operator plan for three subscription accounts.

## Key Decisions

### Route Health Does Not Poison Account Health

Quota exhaustion for `codex:max-1#gpt-5.1-codex-max` must not mark
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

### Codex Max Needs Capability Routes

Three Codex Max accounts are not just three login stores. The mux must know
whether a specific model/task route is unavailable, quota exhausted, temporarily
rate-limited, or auth-dead.

## Current Risks

- Real provider probe endpoints are not yet pinned for Codex/Claude/MCP. The
  schema can express probes, and the runtime can execute them, but provider
  definitions still need verified live endpoints and response semantics.
- Probe execution is intentionally minimal: method, URL, bearer auth, success
  range, retry-after, and one hint header. Request body templating and richer
  header extraction are future work.
- Health persistence is versioned and backward-compatible, but migration policy
  beyond v2 is not yet documented.
- The Codex Max example config is checked in, but `init` still emits the generic
  starter config.
- No release packaging changes have been made in this checkpoint.

## Next Arc

1. Verify real Codex CLI subscription live route probe shape.
2. Decide whether `init` should offer a `--codex-max` starter profile or keep
   the example config as the canonical scaffold.
3. Extend health JSON/text output with last probe evidence fields:
   source, observed_at, retry_after, hint class, and decision.
4. Update TIN-491 and GitHub issue #197 with this checkpoint and the remaining
   provider-verification work.

## Validation

Latest validation at this checkpoint:

```text
just check
all checks passed
```
