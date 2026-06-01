# Stay-Afloat Supervisor Contract
Date: 2026-05-01

Issue context: GitHub `Jesssullivan/oauth-mux#67`; Linear `TIN-738`,
`TIN-859`, `TIN-860`, and `TIN-866`.

## Decision

The portable stay-afloat supervisor is a command contract first. The stable
surface is the foreground tick engine exposed as:

```bash
oauth-mux stay-afloat --once --json
oauth-mux stay-afloat --loop --iterations <n> --interval-ms <ms> --json
oauth-mux stay-afloat --once --execute --json
oauth-mux stay-afloat handoffs --json
```

`oauth-mux daemon tick` is the lower-level alias for the same engine. It is
available for wrapper authors and debugging, but user docs should lead with
`stay-afloat`.

The existing `oauth-mux daemon run/start/stop/status` socket code is not the
production supervisor contract. It is a Unix socket status/control stub that is
useful for local experiments. It is currently unsupported on Windows and does
not perform automatic repair, route refresh, or background scheduling.
The TIN-867 decision is to keep that socket daemon out of the supported
stay-afloat product surface for the current release line. Wrapper authors
should call the foreground tick engine directly.

Service managers are wrappers, not core semantics. `systemctl`, `launchctl`,
Homebrew services, cron, Windows Services, scheduled tasks, containers, and CI
runners may wrap the foreground command later, but none of them define product
behavior.

## Contract Layers

### Layer 1: foreground supervisor tick

This is the cross-platform core.

- It reloads config, health, runtime readiness, route state, and locks on each
  tick.
- Plan mode reports what would happen and does not run probes, repair commands,
  browser/device auth, or secret mutation.
- Execute mode runs at most one admitted non-interactive action per tick.
- Execute mode queues interactive reauth as a redacted handoff event instead of
  silently running it.
- Repeated execute ticks do not append duplicate handoffs for the same route
  while one is pending.
- When an admitted action changes state, the tick re-reads route state before
  rendering JSON.
- Loops are bounded by `--iterations`; unbounded daemonization is outside this
  layer.

The default policy admits only `free_local` and `free_command` budgets. It
refuses provider-spend probes, interactive auth, and mutation unless config
explicitly admits them.

Command-adapter runtime failures are not credential evidence. If a command
probe cannot run because the binary is missing, the selected store is
unavailable, the store is not writable, a session file is missing, a sandbox
blocks execution, or another local runtime precondition fails, the supervisor
must surface `RuntimeReadiness` and a repair action without recording a
dead/degraded OAuth liveness transition. Only an executed provider command or
HTTP probe may update credential liveness.

### Layer 2: local evidence and coordination

This layer does not require a daemon process.

- Recorded liveness lives in the health store.
- Redacted repair, daemon action, handoff, and token-refresh events live in the
  event log.
- Account-scoped repair locks live under the runtime directory.
- `oauth-mux daemon events --json` and `oauth-mux stay-afloat handoffs --json`
  read local state directly.

The event stream is append-only JSONL and must not contain tokens, credential
paths, provider response bodies, or raw upstream CLI output.

### Layer 3: socket stub

The current socket daemon is experimental.

- `daemon run` runs in the foreground on Unix-like platforms.
- `daemon start` forks on Linux/macOS and starts the same loop.
- `daemon status --json` reports `running` with a pid and socket path, or
  `not_running`.
- `daemon status --json` also reports
  `contract:"experimental_socket_stub"`, `production_supported:false`,
  `hosts_stay_afloat:false`, and `wrapper_contract:"foreground_tick"` so
  agents and wrappers do not mistake the socket stub for the stay-afloat
  supervisor.
- The socket handler supports `status`, `stop`, and a placeholder `refresh`
  response.
- It does not host the stay-afloat tick engine in the supported product
  contract.
- It must not be required by first-run, release gates, live QA, or provider
  authoring.

The socket stub can become an implementation detail for a future beta daemon
only through a new promotion slice that aligns it with the foreground
supervisor contract and repeats the daemon promotion gates.

### Layer 4: service wrappers

Wrappers are optional packaging artifacts.

- Homebrew may later provide a `brew services` recipe.
- Linux packages may later ship an optional systemd user unit.
- macOS packages may later ship an optional launchd plist.
- Windows may later ship a service wrapper or scheduled-task recipe.
- npm and curl installs must remain usable without any service manager.

Wrapper docs must call the same foreground command and preserve the same
budgets, event log, handoff behavior, and bounded-loop semantics.

## Runtime Paths

Core paths come from the repo path helpers, not platform service assumptions.

Configuration:

- `OMUX_CONFIG` selects the exact config file.
- `OMUX_CONFIG_DIR` selects the config directory.
- Otherwise config uses XDG on Linux and `~/Library/Application Support` on
  macOS.

State:

- `OMUX_STATE_DIR` selects the state directory.
- Otherwise state uses XDG on Linux and `~/Library/Application Support` on
  macOS.
- The event log is `repair-events.jsonl` under the state directory.

Runtime:

- `XDG_RUNTIME_DIR/oauth-mux` when `XDG_RUNTIME_DIR` is set.
- `/tmp/oauth-mux-$UID` on macOS when no XDG runtime dir is present.
- `$HOME/.local/state/oauth-mux` on other platforms as the current fallback.
- The socket path is `daemon.sock` under the runtime directory.
- Repair locks are under `repair-locks` in the runtime directory.

Wrappers may set these environment variables explicitly, but they should not
invent a second state model.

## JSON Surfaces

Supervisor consumers should read JSON fields, not human text.

Stable inputs:

```bash
oauth-mux doctor runtime --json
oauth-mux route explain --profile <profile> --capability <capability> --json
oauth-mux route select --profile <profile> --capability <capability> --json
oauth-mux repair-plan --profile <profile> --capability <capability> --json
oauth-mux stay-afloat --once --profile <profile> --capability <capability> --json
oauth-mux stay-afloat --once --execute --profile <profile> --capability <capability> --json
oauth-mux stay-afloat handoffs --json
oauth-mux daemon events --json
```

Tick JSON exposes the core supervisor shape:

- `version`
- `tick_index`
- `observed_at`
- `mode`
- `execution_mode`
- `executed`
- `handoff_queued`
- `handoff_pending`
- `message`
- `policy`
- `profile`
- `capability`
- `afloat`
- `selected`
- `summary`
- `executions`
- `routes`

Route entries carry both route evaluation and per-tick decision data. Consumers
should treat `afloat:true` plus a non-null `selected` as the positive route
condition. They should treat `handoff_queued:true` or `handoff_pending:true` as
the signal to surface user-mediated repair.

Runtime repair actions expose `action.diagnostic_command` when the route needs
local runtime proof before any provider call. The diagnostic command is not an
automatic repair action; it is an agent-safe next command for users, wrappers,
or permission brokers to run in the right process boundary.

Each per-route `tick` object also carries deterministic scheduling hints:

- `next_tick_after`: Unix timestamp for the next useful revisit, or `null`.
- `schedule_reason`: why that timestamp was chosen.

The top-level `summary` carries the earliest route-level `next_tick_after` as
`next_tick_after` plus `next_tick_reason`. Wrappers may sleep until that time
or use their own slower cadence. They must not treat the hint as permission to
run unbounded busy loops, spend provider budget, or bypass admission policy.

Process exit codes are not the primary supervisor API. Use command failure for
parse/config/runtime errors, and use JSON fields for route state. `route select`
may exit nonzero when no route is selectable; long-running wrappers should
prefer `route explain` or `stay-afloat --json` when they need a full state
object.

## Tick Semantics

A tick follows this order:

1. Load config and validate it.
2. Expand requested profile/provider/account/capability selectors into routes.
3. Load recorded health.
4. Read runtime readiness for each route.
5. Read account locks and convert active locks into `repair_in_progress`.
6. Combine liveness plus runtime readiness into route selectability.
7. Derive a repair action and daemon admission decision per route.
8. In plan mode, render the decisions.
9. In execute mode, run at most one admitted non-interactive action or queue one
   interactive handoff.
10. Re-read state after an executed action and render the final state.

If any route is already selectable, the tick is a no-op and the route remains
afloat. If no route is selectable, the first admitted action wins. If no action
is admitted, the tick reports the refused action and reason rather than
escalating silently.

## Schedule Semantics

Scheduling is part of the portable foreground contract and must stay
service-manager agnostic. A tick does not daemonize itself. It reports when a
wrapper, CI job, shell hook, or future socket daemon should next re-check the
same route state.

Current schedule reasons:

| Reason | Meaning |
| --- | --- |
| `route_selectable` | A route is already afloat; no wake-up is required. |
| `probe_due` | A diagnostic or admitted probe is useful immediately. |
| `retry_after` | Provider rate-limit evidence supplied a retry-after window. |
| `wait_until` | Quota or cooldown evidence supplied an absolute reset time. |
| `quota_poll` | Quota is exhausted without a known reset; re-check on the conservative quota cadence. |
| `repair_poll` | Another repair owns the account lock; poll the lock on the repair cadence. |
| `runtime_recheck` | Local runtime repair is needed; re-check after the operator or wrapper has time to fix paths, stores, permissions, or sandboxing. |
| `handoff_recheck` | Interactive user-mediated auth is required or pending; re-check after surfacing the handoff. |
| `provider_recheck` | Provider plan/degradation evidence should be revisited later without busy-looping. |
| `no_action` | The route has no follow-up action. |
| `none` | No schedule rule matched. |

Default cadences are intentionally conservative and deterministic:

- repair-lock polling: 30 seconds;
- runtime repair re-check: 5 minutes;
- handoff re-check: 5 minutes;
- quota-without-reset and provider-plan re-checks: 1 hour.

These values are not platform service policy. Service wrappers may choose a
slower interval, but faster intervals should still honor the route-level
`next_tick_after` and admission policy.

## Admission Policy

Every probe or repair action is classified by budget:

- `free_local`
- `free_command`
- `cheap_provider`
- `spend_provider`
- `interactive`
- `mutating`

Default daemon policy:

```json
{
  "allowed_budgets": ["free_local", "free_command"],
  "allow_interactive": false,
  "allow_mutating": false
}
```

This means a default tick may inspect local files, parse health, check runtime
readiness, and run admitted diagnostic commands. It may not spend subscription
quota, open auth flows, or mutate credential stores.

Future policy changes must preserve explicitness:

- provider-spend probes need explicit operator policy;
- interactive auth needs explicit operator policy and handoff/evidence;
- mutation needs explicit operator policy plus writeback admission;
- provider-owned stores such as Codex and Claude remain command-first until
  official direct refresh/writeback behavior is proven.

## Handoff Semantics

Interactive repair is user mediated.

- A tick with an interactive action records a `daemon_handoff` event.
- The event includes route identity, action, command, outcome, and redacted
  booleans, not secrets.
- `stay-afloat handoffs --json` shows pending handoffs.
- `--all` includes historical handoff events.
- A later `route_selectable`, successful `executed`, or successful `noop`
  event for the same route clears the pending handoff.

`TIN-860` should build on this by adding an explicit acknowledgement and refresh
UX, for example a command that lets a user mark a handoff reviewed, run the
upstream login flow, and re-check route state without scraping event logs.

## Wrapper Requirements

A wrapper is acceptable only if it preserves the core contract.

Required wrapper behavior:

- call `oauth-mux stay-afloat --loop` or `oauth-mux daemon tick --loop`;
- set explicit config/state/runtime directories when needed;
- keep loops bounded or use the service manager's restart interval instead of
  hiding an unbounded busy loop inside oauth-mux;
- capture stdout/stderr without exposing secrets;
- leave event logging enabled;
- surface pending handoffs to the user or agent;
- document how to stop, restart, and inspect status without assuming a specific
  shell.

Forbidden wrapper behavior:

- enabling provider-spend probes by default;
- enabling silent interactive auth by default;
- mutating upstream CLI-owned credential stores by default;
- making a wrapper required for first-run success;
- treating Homebrew/systemd/launchd/Windows wrappers as equivalent proof.

## Promotion Gates

Before calling the background daemon production-ready, the project needs:

1. foreground supervisor contract documented and shipped;
2. handoff acknowledgement and refresh UX;
3. daemon socket behavior either aligned with tick JSON or kept clearly
   experimental;
4. stop/status semantics proven on macOS and Linux;
5. Windows daemon behavior implemented or explicitly excluded from package
   docs;
6. wrapper examples for at least one package lane without changing core
   semantics;
7. deterministic scheduler JSON with route-level reasons and top-level summary
   hints;
8. live QA proving timeout, auth failure, quota exhaustion, transient
   rate-limit, runtime permission, and handoff states;
9. docs that distinguish foreground stay-afloat, experimental socket daemon,
   and optional service wrappers.

Until those gates are met, public docs should describe stay-afloat as an
agent-safe foreground beta, not as an always-on background daemon.

## Local Proof

`scripts/e2e-local.sh` includes a no-mutation foreground daemon check using
temporary config, state, and runtime directories. It starts `oauth-mux daemon
run` in the background, waits for `daemon status --json` to report `running`,
stops it through `daemon stop`, waits for the process to exit, and verifies
`daemon status --json` reports `not_running`.

That proof is intentionally narrow. It validates the current socket
status/stop behavior without promoting the socket stub to production
stay-afloat semantics.
