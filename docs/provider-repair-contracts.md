# Provider Repair Contracts

Status: first public contract slice for provider-mediated stay-afloat repair.

`oauth-mux` separates route liveness from local runtime readiness and from the
repair owner. A route can be authenticated but unusable because quota is
exhausted, a scope is insufficient, a local store is unwritable, or an upstream
CLI owns the login flow. Background stay-afloat must not collapse those states
into one generic failure.

## JSON Contract

`repair-plan`, `route explain`, `daemon tick`, `stay-afloat`, and
`daemon supervise` route objects expose an `action` object. The action now has
three distinct identity fields:

```json
{
  "kind": "reauth",
  "mediation": "user_handoff",
  "repair_owner": "upstream_cli_login",
  "interactive": true,
  "mutating": true,
  "budget": "interactive",
  "command": "oauth-mux codex login-device max-1",
  "diagnostic_command": null
}
```

- `kind` is the precise route action.
- `mediation` is how an agent, wrapper, or user should handle the action.
- `repair_owner` identifies who owns credential repair when there is one.

The repair owner values are:

- `upstream_cli_login`: the upstream harness owns login/session repair.
- `oauth_mux_refresh`: oauth-mux owns refresh, subject to explicit writeback
  admission.
- `external_secret_owner`: another secret backend owns rotation or repair.
- `manual_only`: the operator must repair it manually.
- `null`: the action is not credential repair, such as waiting, probing,
  fixing runtime, or inspecting provider scope.

## Action Kinds

The current typed action kinds are:

- `none`: route is selectable.
- `probe_needed`: no recorded evidence exists; probe admission decides whether
  to run.
- `fix_runtime`: local binary, permission, sandbox, store, or session shape is
  not ready.
- `wait_for_repair`: an account-scoped repair lock is active.
- `wait_and_retry`: short provider rate-limit window.
- `wait_for_quota`: quota window is exhausted.
- `wait_for_cooldown`: local cooldown window.
- `scope_or_permission`: credential is live but lacks required scope or route
  permission.
- `resource_or_audience`: credential was minted for another resource or
  audience.
- `provider_plan`: authenticated account is not operable for this capability.
- `try_next_provider`: provider appears degraded.
- `inspect_provider_schema`: route/schema/probe mismatch needs inspection.
- `reauth`: user-mediated or provider-owned login is required.
- `refresh`: oauth-mux-owned refresh would be needed, subject to admission.
- `external_secret_rotation`: external secret owner must rotate or repair.
- `manual_repair`: manual operator repair.

## Mediation Values

The current mediation values are:

- `none`: no action.
- `probe`: probe through the normal budget policy.
- `local_runtime`: fix local runtime/store/session/sandbox state.
- `wait`: wait for quota, rate-limit, cooldown, or lock release.
- `user_handoff`: surface a user-mediated login or verification handoff.
- `oauth_mux_refresh`: oauth-mux-owned refresh path.
- `external_secret_owner`: external rotation or repair path.
- `manual_operator`: manual repair.
- `provider_scope`: provider scope, permission, resource, or audience issue.
- `provider_plan`: subscription or plan capability issue.
- `provider_degraded`: provider-side degradation.
- `schema_inspection`: provider definition or probe schema inspection.

## Provider Notes

Codex:

- Account enrollment can be N+1 and config-dir isolated.
- Upstream CLI login owns session repair.
- A missing session maps to `kind:"reauth"`,
  `mediation:"user_handoff"`, and
  `repair_owner:"upstream_cli_login"`.
- Codex can currently emit a concrete handoff command such as
  `oauth-mux codex login-device max-1`.

Claude:

- Isolated config dirs and `claude` auth-status proof are modeled, but quota
  and repair proof still need paid cohort evidence.
- Upstream CLI login owns session repair.
- Handoff may not have an oauth-mux executable command yet; `command:null` is
  valid when the safe action is to surface upstream login instructions.

Figma:

- PAT and OAuth/MCP bearer-resource modes must stay distinct.
- Scope insufficiency maps to `kind:"scope_or_permission"` and
  `mediation:"provider_scope"`, not auth death.
- Paid/team/plan proof should not promote until route evidence distinguishes
  missing scope from missing subscription or provider degradation.

## Background Rule

The supervised loop may observe, schedule, and queue handoffs. It must not open
browsers, run device auth, perform provider-spend probes, or mutate credential
stores unless the operator explicitly admits that class of action. This is why
`production_supported:false` and `hosts_stay_afloat:false` remain in daemon
status while provider contracts and paid proof continue.
