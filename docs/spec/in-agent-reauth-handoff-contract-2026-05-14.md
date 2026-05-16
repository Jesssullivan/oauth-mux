# In-Agent Reauth Handoff Contract
Date: 2026-05-14
Status: planning contract for TIN-1150. This document defines the agent and
MCP-facing handoff boundary. It does not promote the daemon, Claude, MCP
resource-token, same-thread, or unmanaged harness claims.

Anchors:

- Product bar: `docs/spec/broker-mcp-contract-2026-05-03.md`
- Provider actions: `docs/provider-repair-contracts.md`
- Agent enrollment surface:
  `docs/spec/account-enrollment-agent-contract-2026-05-01.md`
- Daemon boundary: `docs/daemon-boundary.md`

## 1. Contract

An agent may inspect oauth-mux route, runtime, account, proof, and handoff
state. It may ask a user or permission broker to approve a mutating action. It
must not silently run browser/device auth, upstream CLI login, provider-spend
probes, credential rewrites, or session-store repairs.

The supported in-agent behavior is mediation, not credential control:

1. Read no-spend JSON surfaces.
2. Show the exact redacted next action to the user.
3. Wait for user-mediated completion when the action is interactive.
4. Refresh route evidence with an admitted oauth-mux command.
5. Retry the selected managed launch or broker action only after evidence says
   the route is selectable.

This contract uses the same action taxonomy as the CLI:

- diagnostic
- handoff
- probe
- repair
- mutation

Every JSON action exposed to an agent must keep these consent fields explicit:

- `agent_safe`
- `interactive`
- `mutating`
- `spends_provider_calls`
- `budget`
- `mediation`
- `repair_owner`

## 2. No-Spend Surfaces

Agents should start with these no-spend commands or their future MCP tool
equivalents:

```bash
oauth-mux discover --json
oauth-mux providers list --json
oauth-mux accounts list --json
oauth-mux enroll plan <provider> --account <name> --json
oauth-mux doctor runtime --json
oauth-mux route explain --profile <profile> --capability <capability> --json
oauth-mux repair-plan --profile <profile> --capability <capability> --json
oauth-mux stay-afloat --once --profile <profile> --capability <capability> --json
oauth-mux stay-afloat handoffs --json
oauth-mux codex preflight --profile codex-max --capability codex-max --json
```

These surfaces inspect configuration, runtime readiness, recorded health, and
planned actions. They do not open provider auth flows, make live model calls,
spend provider quota, or mutate credential stores by default.

## 3. Handoff Records

A handoff is a user-mediated action. The agent may display it and may record
that it was seen, but it must not run it silently.

Canonical shape:

```json
{
  "kind": "reauth",
  "mediation": "user_handoff",
  "repair_owner": "upstream_cli_login",
  "budget": "interactive",
  "agent_safe": false,
  "interactive": true,
  "mutating": true,
  "spends_provider_calls": false,
  "command": "oauth-mux codex login-device max-1",
  "handoff_plan_command": null,
  "redaction": {
    "token_values_printed": false,
    "raw_account_ids_printed": false,
    "session_ids_printed": false,
    "credential_paths_printed": false
  }
}
```

The command is displayable. It is not agent-executable by default. A future
permission broker may approve execution, but that approval must be explicit and
auditable.

Some upstream-owned providers do not have an oauth-mux executable repair
command yet. In those cases `command` remains `null` and
`handoff_plan_command` points to a no-spend planning command the agent can show
to the user.

After a user completes the upstream login, the agent should ask for an evidence
refresh rather than assuming success:

```bash
oauth-mux stay-afloat refresh --profile <profile> --capability <capability> --json
```

For pending daemon handoffs, agents may acknowledge visibility or clear stale
records with explicit commands:

```bash
oauth-mux stay-afloat handoff ack --provider <provider> --account <account> --json
oauth-mux stay-afloat handoff clear --provider <provider> --account <account> --json
```

Ack is not proof of repair. Clear is not proof of repair. Fresh route evidence
is the proof.

## 4. Provider-Specific Boundaries

### Codex

Codex can emit concrete oauth-mux-owned login handoffs such as:

```bash
oauth-mux codex login-device max-1
```

`codex preflight --json` separates user-mediated auth actions from
spend-confirmed actions:

- `agent_safe_next_actions`: inspect-only next steps.
- `user_mediated_next_actions`: interactive upstream auth handoffs.
- `spend_confirmed_next_actions`: live provider probes or revalidation only
  when explicitly available.

Agents must not collapse those arrays. A login-device action repairs upstream
auth state; it is not a provider-spend revalidation and it is not a daemon
hot-swap.

### Claude

Claude is command-owned. oauth-mux may scaffold an isolated
`CLAUDE_CONFIG_DIR`, but upstream Claude login remains user-mediated:

```bash
env CLAUDE_CONFIG_DIR=<account-dir> claude auth login
```

The narrow proven Claude capability is `auth-status` through:

```bash
claude auth status --json
```

That proves account-store isolation and command-owned auth status only. It does
not prove Claude quota, model-call availability, or in-session stay-afloat.
For Claude reauth, `repair-plan` may return `command:null` with:

```bash
oauth-mux enroll plan claude --account <account> --json
```

That is the safe agent step. It returns the user-mediated `CLAUDE_CONFIG_DIR`
login instruction; oauth-mux still must not run Claude login silently.

### MCP Resource Tokens

MCP HTTP authorization has two separate proof shapes:

- `resource-metadata`: no-secret RFC 9728 protected resource metadata.
- `resource`: bearer token minted for a concrete MCP resource.

Agents must not treat public metadata proof as proof that a user has a live
resource-bound token. Resource-token enrollment, refresh, or rotation remains a
provider/resource-specific handoff until a safe proof surface exists.

## 5. MCP Tool Shape

The future oauth-mux MCP server should mirror CLI semantics rather than invent
a second consent model.

Read-only tools:

- `providers.list`
- `accounts.list`
- `enroll.plan`
- `doctor.runtime`
- `route.explain`
- `repair.plan`
- `stay_afloat.once`
- `handoffs.list`
- `daemon.status`
- `daemon.events`

Handoff lifecycle tools:

- `handoffs.ack`
- `handoffs.clear`
- `stay_afloat.refresh`

Mutation-capable tools:

- `enroll.start`
- `enroll.complete`
- `repair.run`

Mutation-capable tools must require explicit user consent. Their output must
include redacted evidence and must preserve the same consent fields as CLI
JSON. If a provider-owned login, secret setup, or proof run is required, the
tool returns a user-mediated handoff instead of running it silently.

## 6. Redaction Requirements

Agent and MCP surfaces must not emit:

- access tokens, refresh tokens, API keys, or authorization headers;
- raw provider account ids;
- raw email addresses unless already reduced to an approved masked hint;
- raw session ids or transcript ids;
- local credential file paths;
- full provider response bodies from auth or model endpoints.

Allowed fields are labels and coarse booleans:

- provider and account labels from oauth-mux config;
- masked email/account hints already used by redacted diagnostics;
- `*_present` booleans;
- proof status and liveness classes;
- route-state labels such as `available`, `quota_exhausted`,
  `rate_limited`, `tier_insufficient`, `auth_permanently_failed`,
  `credential_unavailable`, `revalidation_needed`, and `not_afloat`;
- exact safe commands that do not include secrets.

## 7. What Is Not Claimed

This contract does not claim:

- same-thread provider continuity across account boundaries;
- mid-turn streaming recovery;
- unmanaged bare-harness daemon hot-swap;
- silent browser/device login;
- silent upstream CLI login;
- non-Codex stay-afloat proof;
- MCP resource-token liveness from metadata proof alone;
- a production background daemon.

The daemon can keep evidence and handoffs warm, but it cannot hot-swap
credentials already loaded by an upstream process unless that harness supports
live reload, app-server auth brokering, proxying, or an oauth-mux-aware
in-agent adapter.

## 8. Acceptance For TIN-1150

The first implementation slice is complete when:

1. This contract is linked from broker, daemon, provider-repair, onboarding,
   and agent-enrollment docs.
2. CLI and planned MCP names preserve the same action taxonomy and consent
   fields.
3. Current Codex, Claude, and MCP resource-token boundaries are explicit.
4. No public-facing doc suggests agents can silently run upstream login or
   mutate credential stores.
5. Future runtime work can add MCP tools against this contract without changing
   the consent vocabulary.
