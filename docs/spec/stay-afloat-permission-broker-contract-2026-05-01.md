# Stay-Afloat Permission Broker Contract
Date: 2026-05-01

Issue context: Linear `TIN-891`, child of `TIN-738`; GitHub
`Jesssullivan/oauth-mux#67`.

## Baseline

`oauth-mux` can keep a Codex Max profile afloat when it runs in the same
process boundary that owns the configured Codex account stores. The 2026-05-01
dogfood check proved the split:

- inside the current Codex sandbox, all configured Codex stores report
  `unwritable_store`;
- outside that sandbox, all three stores are runtime-ready;
- foreground `stay-afloat --once` selects `codex:max-2#codex-max`, keeps
  `max-3` selectable, and parks quota-exhausted `max-1` until its reset.

That means the remaining product gap is not provider liveness. It is how a
wrapper, shell, agent, or user-mediated permission broker should run local
diagnostics and repair handoffs in the right process boundary.

## Decision

The permission broker is a contract, not a daemon.

The stable cross-platform primitive remains:

```bash
oauth-mux stay-afloat --once --profile <profile> --capability <capability> --json
```

When a route is blocked by `fix_runtime`, consumers should inspect:

- `route.runtime.state`;
- `route.action.kind`;
- `route.action.command`;
- `route.action.diagnostic_command`;
- `route.tick.next_tick_after`;
- `route.tick.schedule_reason`.

`action.diagnostic_command` is safe to show to a user or wrapper. It is not an
automatic repair command. It must not update credential liveness, mutate
upstream stores, open a browser, or run provider probes by itself.

## Actor Model

### Human shell

The user owns the normal interactive process boundary. A human shell may run
the diagnostic command directly, then re-run `stay-afloat` or `route explain`.

Expected flow:

```bash
oauth-mux stay-afloat --once --profile codex-max --capability codex-max --json
oauth-mux doctor runtime --provider codex --account max-2 --capability codex-max --json
oauth-mux stay-afloat refresh --profile codex-max --capability codex-max --json
```

### Agent harness

An agent harness should not assume its sandbox can read or write
upstream-owned stores. If `diagnostic_command` is present, the harness should
surface it as a requested local diagnostic or ask its permission broker to run
it. The harness must not rewrite the OAuth store to force progress.

### Shell wrapper

A shell wrapper may run bounded foreground ticks. It may also run
`diagnostic_command` if it is already executing in the user-owned environment
and has access to the same stores. It must preserve stdout/stderr redaction and
must not turn diagnostics into provider probes.

### CI job

CI may run diagnostics only against fixture or explicitly admitted live-provider
profiles. It should prefer temp config/state dirs and never rely on a long-lived
daemon process.

### Service wrapper

Systemd, launchd, Homebrew services, Windows Services, scheduled tasks,
containers, and cron are wrapper choices. They do not define product semantics.
They may call the foreground tick command only after the foreground contract and
permission boundary are proven for the provider.

## State Handling

Runtime states are local preconditions. They are not OAuth liveness:

| Runtime state | Broker behavior |
| --- | --- |
| `ready` | Route may be selected if credential liveness is available. |
| `missing_binary` | Ask the user or package manager to install the upstream CLI. |
| `permission_denied` | Run diagnostics in the owning user context or fix local permissions. |
| `unwritable_store` | Treat as a process-boundary or filesystem ownership problem before any provider claim. |
| `session_unavailable` | Ask the upstream CLI or owner to create the session. |
| `sandbox_blocked` | Ask for an out-of-sandbox diagnostic or a narrower permission grant. |
| `needs_reauth` | Queue or show a user-mediated upstream login handoff. |
| `repair_in_progress` | Wait for the lock and re-check later. |

Only executed provider probes or upstream command adapters may update recorded
credential liveness. Runtime diagnostics may update local operator evidence,
but they must not mark a token dead, degraded, exhausted, or live.

## Command Contract

For `fix_runtime`, JSON must have this shape:

```json
{
  "kind": "fix_runtime",
  "command": null,
  "diagnostic_command": "oauth-mux doctor runtime --provider codex --account max-2 --capability codex-max --json"
}
```

`command:null` means there is no admitted automatic repair command.

`diagnostic_command` means a consumer can request more local evidence. The
command should be re-run from a process boundary that can see the provider's
configured store.

## Admission Rules

The default daemon policy remains conservative:

- admits `free_local` and `free_command`;
- refuses provider-spend probes;
- refuses silent interactive auth;
- refuses silent mutation.

Permission brokers may request user approval to cross a process boundary, but
approval to run a diagnostic is not approval to mutate credentials. Reauth and
refresh still follow the provider repair owner:

- `upstream_cli_login`: hand off to the provider CLI;
- `oauth_mux_refresh`: run only when writeback is admitted;
- `external_secret_owner`: ask the external owner to rotate or repair;
- `manual_only`: show manual repair instructions.

## Provider Author Guidance

New harness adapters should define runtime preconditions before live proof:

- required binaries;
- config dir env var;
- writable store paths;
- session files;
- upstream CLI login ownership;
- whether command probes are free, cheap, or spend provider budget.

Provider authors should add fixture coverage for runtime failures separately
from credential failures. A sandboxed write failure is not a revoked token.

## Product Readiness Gate

The background daemon should remain non-product until this contract has live
evidence for at least:

- Codex account stores under a normal shell and an agent sandbox;
- one command-owned provider such as Claude or FlakeHub/Determinate;
- one HTTP-token provider such as GitHub, Linear, Vercel, Figma, or MCP;
- one wrapper recipe that calls foreground ticks without relying on platform
  service-manager semantics.

Until then, public docs should lead with foreground commands and describe
service managers as optional wrapper examples.

## Next Slice

The next implementation slice should add a small wrapper-author section to the
public docs and one fixture/E2E case that asserts `diagnostic_command` remains
present for runtime repair while `command` remains `null`.

Implementation note, 2026-05-01: the public adoption doc now includes the
wrapper-author contract, and the clean first-run E2E asserts that
`repair-plan`, `route explain`, and `stay-afloat --once` keep runtime repair
as `command:null` plus a user/broker-visible `diagnostic_command`.
