# Account Enrollment And Agent Contract
Date: 2026-05-01

Issue context: GitHub `Jesssullivan/oauth-mux#67` and `#68`; Linear `TIN-736`,
`TIN-738`, and `TIN-891`.

## Baseline

Codex is product-proven for the current paid cohort path, but the first-run
surface is still more provider-specific than the final product should be.
Claude and Figma have provider definitions and partial proof, but not a boring
N-account enrollment contract.

The goal is a stable shape where users and agents can add the N+1 account,
inspect what changed, and keep work afloat without memorizing each provider's
storage quirks.

The paid proof cohort in
`docs/spec/paid-multi-account-proof-cohort-2026-05-01.md` is the first planned
stress test for this contract: four `codex-max` routes plus lower-tier Codex
contrast, three Claude Code account/billing shapes, and three Figma
token/resource shapes. Current Codex route health remains capability-scoped:
Spark/mini or dashboard-credit availability does not imply `codex-max`
availability.

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
mutation as available only where provider-owned consent flows are implemented.

The first consented mutations are Codex, Claude, and Figma:

```bash
oauth-mux enroll codex --account max-4 --confirm-enroll --json
oauth-mux enroll claude --account work --confirm-enroll --json
oauth-mux enroll figma --account design --mode pat --secret-env OMUX_FIGMA_DESIGN_PAT --confirm-enroll --json
```

Confirmed Codex enrollment mutates only oauth-mux-owned state: active config,
Codex Max/Mini profile routes, and the isolated local Codex account directory.
It does not run `codex login`, open browser/device auth, or spend provider
calls. The output returns the provider-owned login handoff as a next command.

Confirmed Claude enrollment follows the same boundary: active oauth-mux config,
the `claude` profile route, and an isolated `CLAUDE_CONFIG_DIR` are scaffolded,
then `claude auth login` is returned as a user-mediated handoff. oauth-mux does
not run the Claude login command or rewrite Claude-owned credential state.

Confirmed Figma enrollment is config-only. It adds a mode-specific Figma
provider/profile route and an env-backed secret reference, but does not create
token material, open OAuth, or run a proof probe. OAuth bearer, PAT, and
plan/file metadata modes remain separate route shapes.

## User Stories

### Story A: user adds a fourth Codex account

The user wants one more Codex subscription account without breaking the current
paid-cohort setup.

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

Expected flow:

```bash
oauth-mux enroll plan claude --account work --json
oauth-mux enroll claude --account work --confirm-enroll --json
env CLAUDE_CONFIG_DIR=<account-dir> claude auth login
oauth-mux doctor runtime --provider claude --account work --capability auth-status --json
oauth-mux accounts list --provider claude --json
oauth-mux stay-afloat --once --profile claude --capability auth-status --json
```

The first proof target is account-store isolation and `auth-status`, not
automatic quota repair.

### Story C: user adds multiple Figma identities

Figma needs auth-mode separation. OAuth bearer, PAT, and plan/file metadata
routes must not collapse into one "Figma works" claim.

Expected flow:

```bash
oauth-mux enroll plan figma --account service --mode pat --json
oauth-mux enroll figma --account service --mode pat --secret-env OMUX_FIGMA_SERVICE_PAT --confirm-enroll --json
export OMUX_FIGMA_SERVICE_PAT=<figma-token>
oauth-mux accounts list --provider figma --json
oauth-mux probe --provider figma-pat --account service --capability identity-pat --json
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
- redacted auth-bound identity hints when a provider can expose them safely;
- account-level runtime readiness;
- writeback admission;
- per-capability proof, runtime readiness, recorded liveness, selectability,
  proof requirements, and safe action shape;
- agent-safe next commands.

For Codex accounts, `auth_identity` may report a masked email hint, a short
account-id hash, and presence/source booleans for ChatGPT account and plan
claims. It must not print raw email, token material, auth file paths, session
ids, or unredacted account ids. This gives agents enough information to ask for
the right labeled OAuth handoff (`oauth-mux codex login-device <account>`)
without reading Codex auth files directly.

`enroll plan --json` reports:

- requested provider, account, and mode;
- whether the provider is already configured;
- existing configured accounts with secret backend names only;
- ordered steps, each labeled for agent safety, interactivity, mutation, and
  provider-call spend;
- safe next commands;
- the future provider-neutral mutation command with `available:false`.

For Codex, Claude, and Figma, that command is now available and points to
`oauth-mux enroll <provider> --account <name> --confirm-enroll`.

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

The current detailed handoff and consent contract is
`docs/spec/in-agent-reauth-handoff-contract-2026-05-14.md`. This section is the
enrollment-side summary.

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

For the current Codex, Claude, and Figma implementations, the mutation-capable tool
equivalent should expose the same shape as `enroll <provider>
--confirm-enroll`: config/store scaffolding only, with provider login, secret,
or proof setup returned as a user-mediated handoff.

## Implementation Slices

1. Shipped `accounts list` as the provider-neutral inventory surface.
2. Shipped `enroll plan <provider>` to print the exact provider-specific setup
   steps without mutation.
3. Shipped Codex N+1 enrollment as
   `enroll codex --account <name> --confirm-enroll`.
4. Shipped Claude account-store enrollment as
   `enroll claude --account <name> --confirm-enroll`.
5. Shipped Figma OAuth/PAT/plan enrollment scaffolding as
   `enroll figma --account <name> --mode <oauth|pat|plan> --confirm-enroll`.
6. Define the MCP tool schema against the same JSON surfaces.
