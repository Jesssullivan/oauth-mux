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

## User Stories

### Story A: user adds a fourth Codex account

The user wants one more Codex subscription account without breaking the current
three-account setup.

Expected flow:

```bash
oauth-mux accounts list --provider codex --json
oauth-mux codex config-candidate --store-root ~/.local/share/oauth-mux/codex --json
oauth-mux codex config-merge --candidate /tmp/oauth-mux-codex-max.config.json --json
oauth-mux codex login-device max-4
oauth-mux doctor runtime --provider codex --account max-4 --capability codex-max --json
oauth-mux stay-afloat refresh --profile codex-max --capability codex-max --json
```

Future provider-neutral shape:

```bash
oauth-mux enroll codex --account max-4
```

### Story B: user adds work and personal Claude accounts

Claude is command-owned. oauth-mux should isolate `CLAUDE_CONFIG_DIR` per
account, hand off login to the Claude CLI, and avoid silently rewriting
Claude-owned state.

Expected future flow:

```bash
oauth-mux enroll claude --account work
oauth-mux enroll claude --account personal
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
- `providers.list`
- `doctor.runtime`
- `route.explain`
- `stay_afloat.once`
- `handoffs.list`

Mutation-capable tools such as `enroll.start`, `enroll.complete`, or
`repair.run` must require explicit user consent and must return redacted
evidence. MCP tools should preserve the same action taxonomy as the CLI:
diagnostic, handoff, probe, repair, and mutation.

## Next Implementation Slices

1. Land `accounts list` as the provider-neutral inventory surface.
2. Add `enroll plan <provider>` to print the exact provider-specific setup
   steps without mutation.
3. Promote Codex N+1 enrollment from provider-specific helpers into
   `enroll codex --account <name>`.
4. Add Claude account-store config candidate and runtime proof.
5. Add Figma OAuth/PAT enrollment plan and proof fixtures.
6. Define the MCP tool schema against the same JSON surfaces.
