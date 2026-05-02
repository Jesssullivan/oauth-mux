# Background Stay-Afloat Daemon Contract
Date: 2026-05-02

Issue context: Linear `TIN-897`, child of `TIN-738`; GitHub
`Jesssullivan/oauth-mux#67`. This builds on
`docs/spec/stay-afloat-supervisor-contract-2026-05-01.md`,
`docs/spec/stay-afloat-permission-broker-contract-2026-05-01.md`, and
`docs/spec/paid-multi-account-proof-cohort-2026-05-01.md`.

## Baseline

`oauth-mux` can already keep a route set understandable and selectable through
foreground commands:

```bash
oauth-mux route explain --profile <profile> --capability <capability> --json
oauth-mux route select --profile <profile> --capability <capability> --json
oauth-mux stay-afloat --once --profile <profile> --capability <capability> --json
oauth-mux stay-afloat --loop --iterations <n> --interval-ms <ms> --profile <profile> --capability <capability> --json
```

The current Codex dogfood state proves that route-scoped fallback works:
`codex:max-1#codex-max` is parked as quota exhausted until its reset window,
`codex:max-2#codex-max` is selected, and `codex:max-3#codex-max` remains a
selectable fallback. That is real product evidence.

The stronger product goal is not proven yet:

> install oauth-mux, enroll N accounts, and have user or agent work stay afloat
> while subscriptions pass through quota, rate limit, logged-out, stale-token,
> runtime-boundary, and reauth states.

That goal needs a background daemon, but it also needs a precise definition of
"seamless." A daemon can keep route state, schedules, events, and reauth
handoffs warm. It cannot transparently rewrite credentials already loaded in an
upstream harness process unless the harness supports live reload or the harness
request path is mediated by oauth-mux.

## Decision

The production daemon should promote the existing foreground tick engine. It
must not introduce a second muxing model.

The daemon's stable responsibilities are:

- run the same policy-gated stay-afloat tick loop in the background;
- keep the latest route snapshot available for users, wrappers, and agents;
- maintain redacted event, handoff, and execution evidence;
- honor route-level `next_tick_after` and `schedule_reason`;
- run only admitted background actions;
- surface user-mediated auth and runtime diagnostics as handoffs;
- expose status without depending on any one service manager.

The daemon's non-responsibilities are equally important:

- no silent provider-spend probes by default;
- no silent browser/device login;
- no silent mutation of upstream CLI-owned stores;
- no assumption that `systemctl`, `launchctl`, Homebrew services, cron, or
  Windows Services define product semantics;
- no claim that an already-running harness process can be hot-swapped unless
  that harness has a proven reload, restart, proxy, or in-agent mediation path.

## Seamless Handoff Model

There are three levels of "seamless" support. Public docs and demos must name
the level being shown.

### Level 1: prepared fallback

The daemon keeps route state fresh enough that the next mediated action can
pick a healthy account without a user re-running diagnostics.

This is what the product can realistically support first for Codex, Claude,
Figma, GitHub, Linear, Vercel, FlakeHub, and MCP-like providers.

Required mediation point:

- `oauth-mux exec`;
- a shell wrapper;
- an agent calling `route select` or `stay-afloat --once`;
- a package wrapper that calls the foreground tick contract.

If an account caps out during a long-running upstream process, Level 1 prepares
the next launch or command. It does not mutate the already-running process.

### Level 2: supervised restart or relaunch

The wrapper owns the harness process and can restart it with a new selected
route when the current route becomes unusable.

Required mediation point:

- an oauth-mux-owned command wrapper;
- an editor/agent integration that can restart a child harness;
- a CLI launcher that treats route selection as part of process startup.

This can feel seamless to a user when the harness session is restart-tolerant.
It is still not hot credential reload.

### Level 3: per-request muxing

Every provider request passes through oauth-mux or an oauth-mux-aware protocol
surface. The mux can reroute a single request without restarting the harness.

Required mediation point:

- an HTTP/API proxy;
- an MCP tool/resource server;
- an in-agent provider adapter;
- a harness-native credential reload or account-switch API.

This is the strongest product shape, but it is provider and harness specific.
Codex and Claude command-owned sessions should not be advertised at Level 3
until their reload or proxy semantics are explicitly proven.

## Background Daemon Shape

The beta background daemon should be a portable foreground process first. A
service manager may keep it alive, but service managers remain wrappers.

Core daemon loop:

1. load config, health, runtime state, locks, and event state;
2. expand configured profiles into routes;
3. run one `stay-afloat` execute tick under daemon policy;
4. write a redacted route snapshot;
5. expose status, events, and handoffs;
6. sleep until the earliest admitted `next_tick_after`, bounded by policy;
7. stop cleanly on signal or explicit stop command.

Default policy:

```json
{
  "allowed_budgets": ["free_local", "free_command"],
  "allow_interactive": false,
  "allow_mutating": false
}
```

Provider-spend probes, interactive auth, and credential mutation require
explicit operator policy plus redacted evidence.

## Cross-Platform Requirements

Core behavior must work without platform-specific assumptions:

- no required `systemctl`;
- no required `launchctl`;
- no required Homebrew services;
- no required cron;
- no required Windows Services;
- no shell-specific startup requirement.

The core process should be runnable as:

```bash
oauth-mux daemon run --stay-afloat --profile <profile> --capability <capability>
```

The exact flag spelling can change during implementation, but the product
boundary should not: a foreground process hosts the same stay-afloat tick
engine and optional service wrappers only keep that process running.

Wrapper examples can come later:

- Homebrew service wrapper;
- macOS launchd plist;
- Linux systemd user unit;
- Windows scheduled task or service wrapper;
- container/CI wrapper;
- shell hook for agents and terminal sessions.

Each wrapper must preserve daemon policy, event logging, handoff visibility,
and stop/status inspection.

## Harness Mediation Contracts

### Codex

Codex currently behaves as a command-owned session. `CODEX_HOME` selection is
the main route injection boundary.

Supported near-term product shape:

- daemon keeps Codex route evidence and handoffs warm;
- `oauth-mux exec --profile codex-max -- codex ...` launches future Codex
  commands with the selected account;
- a Codex-specific wrapper can relaunch a child Codex process when the selected
  route changes;
- direct hot-swap inside this already-running Codex session is not promised.

### Claude

Claude is also command-owned. `CLAUDE_CONFIG_DIR` isolation and `claude auth
status` are the first proven surfaces.

Supported near-term product shape:

- daemon keeps account-store readiness and auth-status evidence warm;
- login remains user-mediated through Claude CLI handoff;
- quota and usage behavior need paid cohort proof before background claims.

### Figma

Figma has multiple auth shapes: OAuth bearer, PAT, plan token, and MCP remote
resource auth. These must stay separate.

Supported near-term product shape:

- daemon can keep low-impact identity/resource status warm when policy admits;
- PAT and plan-token stores can become stronger candidates for automatic
  refresh or rotation only when ownership is explicit;
- OAuth/browser flows remain user-mediated until a safe app flow is proven.

### MCP and in-agent surfaces

MCP should expose visibility before mutation:

- `accounts.list`;
- `providers.list`;
- `route.explain`;
- `stay_afloat.once`;
- `handoffs.list`;
- `enroll.plan`.

Mutation-capable tools must require explicit user consent and return redacted
evidence. They should not silently run browser/device auth or spend provider
quota.

## Implementation Slices

### D0: contract and tracking

- Create this production daemon contract.
- Link it from the daemon boundary and product gap map.
- Attach it to `TIN-897` and GitHub `#67`.

### D1: daemon snapshot status

- Persist the latest stay-afloat tick summary as a redacted daemon snapshot.
- Add status JSON fields for `last_tick_at`, `next_tick_after`,
  `next_tick_reason`, `afloat`, `selected`, and `handoff_pending`.
- Keep `production_supported:false` until a supervised loop exists.

Implementation note, 2026-05-02: this slice now writes
`daemon-snapshot.json` under the oauth-mux state directory after each
stay-afloat/daemon tick. `oauth-mux daemon status --json` exposes the latest
snapshot under `stay_afloat` while still reporting
`production_supported:false` and `hosts_stay_afloat:false`.
The snapshot now includes a `claim` object. `claim.level:"prepared_fallback"`
is Level 1: route state is warm enough for the next mediated
`stay-afloat launch` / `exec` boundary. The object explicitly keeps
`current_process_hotswap:false`, `supervised_restart:false`, and
`per_request_muxing:false` so agents and websites do not overclaim daemon
behavior from a healthy snapshot.

### D2: supervised stay-afloat loop

- Add an opt-in daemon mode that hosts the foreground tick engine.
- Stop cleanly.
- Run no provider-spend probes by default.
- Reuse account locks, handoffs, event logs, and scheduler hints.
- Prove macOS and Linux stop/status behavior.

Implementation note, 2026-05-02: the beta loop is available as:

```bash
oauth-mux daemon run --stay-afloat --profile <profile> --capability <capability>
oauth-mux daemon supervise --profile <profile> --capability <capability>
```

It writes the normal daemon pid file, records beta loop metadata under the
runtime directory, runs the same stay-afloat tick engine with execute mode
enabled, and updates the redacted `stay_afloat` status snapshot after each
tick. `daemon status --json` reports `contract:"experimental_supervised_loop"`
and `stay_afloat_loop.hosted:true` while the loop is running. The same
`stay_afloat_loop` object includes the hosted selector, interval, iteration
bound, and execution mode so dogfood status can prove which route set is being
supervised without reading process argv or logs. Status still reports
`production_supported:false` and `hosts_stay_afloat:false` until wrapper docs and
soak proof promote the product surface.

Implementation note, 2026-05-02: the loop sleep path now honors the earliest
summary `next_tick_after` emitted by route decisions, bounded by the operator's
`--interval-ms`. A due or overdue route wakes the next tick immediately; a
far-future reset still respects the configured maximum cadence. This is only a
scheduler improvement and does not grant provider-spend, interactive, or
mutating admission.

### D3: wrapper recipes

- Add package-neutral wrapper docs first.
- Add Homebrew service, launchd, systemd user, Windows, and container examples
  only as optional wrappers.
- Prove each wrapper preserves policy and event/handoff visibility.

### D4: mediation adapters

- Promote `oauth-mux exec` and shell wrappers as Level 1 mediation.
- Add a Codex wrapper story for selected-account launch and supervised restart.
- Add MCP/in-agent tools for route visibility and handoff surfacing.
- Consider request-level proxying only where the harness protocol can support
  Level 3 per-request muxing.

Implementation note, 2026-05-02: `oauth-mux stay-afloat launch` is now the
Level 1 startup boundary. It preflights from recorded evidence, delegates to
`exec` for normal validation, retries the next selectable route if launch-time
validation reclassifies the first route, and refuses to start the target when
no route remains selectable.

### D5: paid cohort soak

- Run the `TIN-895` seven-day foreground soak first.
- Then run daemon beta soak on the same cohort.
- Public claims graduate only for the exact provider, account shape, and
  mediation level proven.

## Claim Policy

Allowed now:

- foreground stay-afloat selects a usable route from recorded liveness and
  runtime readiness;
- Codex multi-account fallback is proven for the current dogfood state;
- daemon work is in progress toward background supervision.

Allowed after D2 and soak evidence:

- background daemon keeps route state and handoffs warm for proven profiles;
- optional wrappers can keep the daemon process running on tested platforms.

Not allowed without Level 2 or Level 3 proof:

- "oauth-mux will seamlessly hot-swap this already-running Codex session";
- "background daemon silently reauths provider-owned CLI sessions";
- "universal OAuth muxing is proven for every AI harness";
- "Figma" or "Claude" are fully proven without naming the exact capability and
  account/billing shape.

## Immediate Product Answer

If the current Codex session caps out, oauth-mux should be able to identify the
next selectable Codex route from recorded evidence. It will not automatically
replace the credentials inside this already-running Codex process unless this
session was launched through a mediation layer that can relaunch, reload, or
proxy requests through oauth-mux.

That is the gap this contract exists to close.
