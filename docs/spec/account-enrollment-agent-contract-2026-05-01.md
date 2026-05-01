# Account Enrollment And Agent Contract
Date: 2026-05-01

Issue context: GitHub `Jesssullivan/oauth-mux#67` and `#68`; Linear `TIN-736`,
`TIN-738`, and `TIN-891`.

## Baseline

Codex is product-proven for the current three-account path, but the first-run
surface is still more provider-specific than the final product should be.
Claude and Figma have provider definitions and partial proof, but not a boring
N-account enrollment contract.

The goal is a stable shape where users and agents can add the N+1 account,
inspect what changed, and keep work afloat without memorizing each provider's
storage quirks.

## Product Contract

Enrollment is a three-layer contract:

1. **Visibility**: list configured accounts, runtime readiness, capability
   proof, and recorded liveness without reading secret values.
2. **Admission**: explain whether an action is a diagnostic, a handoff, a
   provider-spend probe, or mutating repair.
3. **Mutation**: run only explicit provider-owned setup/login flows, with user
   consent and redacted evidence.

This PR starts with visibility through:

```bash
oauth-mux accounts list --json
oauth-mux accounts list --provider codex --json
```

`accounts list` is intentionally non-mutating. It is an agent-safe inventory
surface for deciding which provider-specific or future provider-neutral
enrollment command should run next.

The second slice adds non-mutating admission planning through:

```bash
oauth-mux enroll plan <provider> --json
oauth-mux enroll plan codex --account max-4 --json
oauth-mux enroll plan figma --account work --mode pat --json
```

`enroll plan` does not mutate config or auth state. It labels every proposed
step with `agent_safe`, `interactive`, `mutating`, and
`spends_provider_calls`, and it explicitly reports provider-neutral enrollment
mutation as unavailable until provider-owned consent flows are implemented.

The first consented mutation is Codex-only:

```bash
oauth-mux enroll codex --account max-4 --confirm-enroll --json
```

Confirmed Codex enrollment mutates only oauth-mux-owned state: active config,
Codex Max/Mini profile routes, and the isolated local Codex account directory.
It does not run `codex login`, open browser/device auth, or spend provider
calls. The output returns the provider-owned login handoff as a next command.

## User Stories

### Story A: user adds a fourth Codex account

The user wants one more Codex subscription account without breaking the current
three-account setup.

Expected flow:

```bash
oauth-mux accounts list --provider codex --json
oauth-mux enroll plan codex --account max-4 --json
oauth-mux enroll codex --account max-4 --confirm-enroll --json
oauth-mux codex login-device max-4
oauth-mux doctor runtime --provider codex --account max-4 --capability codex-max --json
oauth-mux stay-afloat refresh --profile codex-max --capability codex-max --json
```

Provider-neutral shape:

```bash
oauth-mux enroll codex --account max-4 --confirm-enroll
```

If the active config is not already a Codex Max/Mini mux shape, the command
refuses and returns the existing `codex config-candidate` / `config-merge`
path. This keeps migration from single-account Codex separate from N+1
enrollment.

### Story B: user adds work and personal Claude accounts

Claude is command-owned. oauth-mux should isolate `CLAUDE_CONFIG_DIR` per
account, hand off login to the Claude CLI, and avoid silently rewriting
Claude-owned state.

Expected future flow:

```bash
oauth-mux enroll claude --account work
oauth-mux enroll claude --account personal
oauth-mux enroll plan claude --account work --json
oauth-mux accounts list --provider claude --json
oauth-mux stay-afloat --once --profile claude --capability auth-status --json
```

The first proof target is account-store isolation and `auth-status`, not
automatic quota repair.

### Story C: user adds multiple Figma identities

Figma needs auth-mode separation. OAuth bearer, PAT, and plan/file metadata
routes must not collapse into one "Figma works" claim.

Expected future flow:

```bash
oauth-mux enroll figma --account work --mode oauth
oauth-mux enroll figma --account service --mode pat
oauth-mux enroll plan figma --account service --mode pat --json
oauth-mux accounts list --provider figma --json
oauth-mux probe --provider figma --account service --capability identity-pat --json
```

The proof gate must distinguish `scope_insufficient`, revoked token,
resource/file permission, rate limit, and provider degradation.

### Story D: agent discovers the next safe action

An agent should start with inventory, not mutation:

```bash
oauth-mux discover --json
oauth-mux accounts list --json
oauth-mux enroll plan <provider> --json
oauth-mux doctor runtime --json
oauth-mux route explain --profile <profile> --capability <capability> --json
oauth-mux stay-afloat --once --profile <profile> --capability <capability> --json
```

If `action.diagnostic_command` is present, the agent surfaces that command to
the user or permission broker. If a handoff is queued, the agent shows the
handoff rather than trying to run browser/device auth silently.

## JSON Shape

`accounts list --json` reports:

- configured provider/account identity;
- provider support and proof status;
- secret backend name, not secret values;
- account-level runtime readiness;
- writeback admission;
- per-capability proof, runtime readiness, recorded liveness, selectability,
  and safe action shape;
- agent-safe next commands.

`enroll plan --json` reports:

- requested provider, account, and mode;
- whether the provider is already configured;
- existing configured accounts with secret backend names only;
- ordered steps, each labeled for agent safety, interactivity, mutation, and
  provider-call spend;
- safe next commands;
- the future provider-neutral mutation command with `available:false`.

For Codex, that command is now available and points to
`oauth-mux enroll codex --account <name> --confirm-enroll`.

Account state is intentionally coarse:

| State | Meaning |
| --- | --- |
| `configured` | Account is in config, but no liveness evidence is recorded. |
| `available` | At least one account or capability health record is live and available. |
| `has_evidence` | Health evidence exists but no live-available capability is recorded. |
| `action_needed` | Runtime is not ready, so provider liveness should not be inferred. |

## Provider Requirements

### Codex

- N-account `CODEX_HOME` isolation.
- Device login handoff per account.
- `codex-mini` and `codex-max` capability proof.
- Runtime diagnostics across normal shell and agent sandbox.
- Quota-exhausted, rate-limited, auth-dead, and store-unwritable fixtures.

### Claude

- N-account `CLAUDE_CONFIG_DIR` isolation.
- `claude auth status --json` proof per account.
- Login handoff owned by Claude CLI.
- Runtime and keychain behavior documented without relying on undocumented
  hashes as public product semantics.
- Quota/usage proof only after low-impact status proof is stable.

### Figma

- Separate OAuth bearer, PAT, and resource/file routes.
- Explicit scopes and scope-insufficient classification.
- Redacted fixtures for 200 identity, 401 revoked, 403 insufficient scope,
  file/resource permission failure, 429, and 5xx.
- No provider-level promotion until auth modes are proven separately.

## MCP And In-Agent Surface

The MCP-facing surface should expose inventory and explanation before mutation:

- `accounts.list`
- `enroll.plan`
- `providers.list`
- `doctor.runtime`
- `route.explain`
- `stay_afloat.once`
- `handoffs.list`

Mutation-capable tools such as `enroll.start`, `enroll.complete`, or
`repair.run` must require explicit user consent and must return redacted
evidence. MCP tools should preserve the same action taxonomy as the CLI:
diagnostic, handoff, probe, repair, and mutation.

For the current Codex implementation, the mutation-capable tool equivalent
should expose the same shape as `enroll codex --confirm-enroll`: config/store
scaffolding only, with provider login returned as a user-mediated handoff.

## Next Implementation Slices

1. Land `accounts list` as the provider-neutral inventory surface.
2. Land `enroll plan <provider>` to print the exact provider-specific setup
   steps without mutation.
3. Land Codex N+1 enrollment as
   `enroll codex --account <name> --confirm-enroll`.
4. Add Claude account-store config candidate and runtime proof.
5. Add Figma OAuth/PAT enrollment mutation planning and proof fixtures.
6. Define the MCP tool schema against the same JSON surfaces.
