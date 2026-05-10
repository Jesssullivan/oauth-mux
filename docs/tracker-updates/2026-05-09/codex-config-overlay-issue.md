# P1: Preserve Codex config and experimental settings in managed overlay

## Problem

`oauth-mux codex` currently creates a temporary `CODEX_HOME` and writes a fresh
managed `config.toml` containing only the oauth-mux proxy provider override.
That protects canonical `~/.codex/config.toml` from mutation, but it can also
mask normal Codex user-level settings that Codex would load from
`CODEX_HOME/config.toml`.

This matters for behavioral parity. Codex configuration controls
model/provider defaults, approval and sandbox policy, MCP servers, hooks,
rules, feature flags, and experimental settings. In particular, `/experimental`
or `[features]`-style settings such as `features.apps`, `features.memories`,
`features.multi_agent`, `features.prevent_idle_sleep`, `features.unified_exec`,
and legacy `experimental_*` keys must be preserved or deliberately overridden
while using oauth-mux.

Official Codex config docs say Codex reads user config from
`~/.codex/config.toml`, project overrides from `.codex/config.toml`, and applies
precedence: CLI flags / `--config`, profiles, project config, user config,
system config, defaults. See:

- https://developers.openai.com/codex/config-basic
- https://developers.openai.com/codex/config-reference

## Current Evidence

The first implementation slice is landed in `src/adapters/codex/main.zig`.
`writeManagedConfigToml()` now reads the canonical Codex config authority home
(`OMUX_CODEX_CONFIG_HOME`, then parent `CODEX_HOME`, then `~/.codex`) and writes
a managed overlay config that preserves unrelated behavior settings while
replacing only the oauth-mux-owned provider selection:

```toml
model_provider = "oauth_mux_openai"

[model_providers.oauth_mux_openai]
name = "oauth-mux OpenAI proxy"
base_url = "http://127.0.0.1:<port>/backend-api/codex"
wire_api = "responses"
requires_openai_auth = true
```

Current behavior:

- preserves user config such as model defaults, approval/sandbox policy,
  `[features]`, legacy `experimental_*`, MCP servers, profiles, and custom
  non-managed provider definitions;
- strips all `model_provider = ...` lines, including profile-scoped entries, so
  the managed session selects `oauth_mux_openai`;
- strips stale `[model_providers.oauth_mux_openai]` and nested managed-provider
  subtables before appending the fresh proxy provider;
- keeps config authority independent from session authority, so
  `--session-home`, `OMUX_CODEX_SESSION_HOME`, and `--isolated-session-store`
  do not hide user behavior config;
- rejects forwarded Codex `--config` / `-c` assignments that attempt to override
  `model_provider`, profile-scoped `*.model_provider`, or
  `model_providers.oauth_mux_openai*` before spawning Codex.

Status evidence remains redacted. `session_started` reports booleans/counts for
config passthrough, and failed forwarded override attempts emit
`config_passthrough_check` with key classes and counts, not raw values or paths.

## Desired Behavior

Managed Codex should preserve native Codex behavior except for the minimal
oauth-mux-owned auth/config override required for brokering.

The adapter should classify config state into:

- mux-owned overrides: `model_provider = "oauth_mux_openai"` and
  `[model_providers.oauth_mux_openai]` base URL / auth shape;
- user/harness behavior settings: approval policy, sandbox, profiles,
  `[features]`, legacy `experimental_*`, MCP servers, hooks, rules, model
  defaults, file opener, personalities, subagents, etc.;
- secrets or paths that must stay redacted in status output.

## Acceptance Criteria

- [x] Discover and document the exact Codex config files/layers that are affected by
  changing `CODEX_HOME`.
- [x] Managed overlay preserves user-level Codex config semantics by default,
  either by safe TOML merge/copy plus oauth-mux override, or by an equivalent
  CLI `--config` strategy if that proves more robust.
- [x] oauth-mux overrides only the keys it owns for proxying; unrelated config keys
  survive.
- [x] Existing `[model_providers.*]`, profiles, `[features]`, `experimental_*`, MCP
  server config, hooks/rules config, approval/sandbox settings, and model
  defaults are preserved unless explicitly incompatible.
- [x] Conflicts are typed and redacted. Status should report counts/classes such as
  `config_passthrough:true`, `user_config_present:true`,
  `overridden_keys:["model_provider","model_providers.oauth_mux_openai"]`, but
  must not print token material, raw paths, or user config contents.
- [x] Add a stub smoke fixture with canonical `config.toml` containing
  representative `[features]`, `experimental_*`, MCP, approval/sandbox, and
  profile settings. The spawned stub Codex should observe those settings in the
  managed overlay while still seeing the oauth-mux proxy provider.
- [x] Add a regression for a pre-existing user `model_provider` /
  `[model_providers.openai]` or custom provider: oauth-mux should preserve the
  provider definition while selecting `oauth_mux_openai` for the managed
  session.
- [x] Preserve existing guarantees: do not mutate canonical `~/.codex/config.toml`,
  do not clobber account-local configs, and keep `--isolated-session-store`
  semantics explicit.

## Product Boundary

This is parity/hygiene for the managed Codex frame. It is not a quota-handoff
proof by itself and must not be framed as Level 3 success. It supports the
product bar by making `oauth-mux codex` behave like native Codex while
oauth-mux owns only the broker-required auth/proxy boundary.
