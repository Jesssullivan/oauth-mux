# Daemon Boundary

The daemon exists, but it is not a production dependency yet.

## Current Decision

Keep daemon usage optional until provider-specific refresh semantics are proven
for each OAuth-backed harness. The default production path remains explicit
selection, explicit probe, env injection, and exec handoff.

For the current product line, the socket daemon is not the stay-afloat product
surface. It remains local experimental status/control plumbing. Wrappers,
package recipes, CI jobs, and agents should call the foreground tick contract:
`oauth-mux stay-afloat ...` or the lower-level `oauth-mux daemon tick ...`.
If a production background daemon is added later, it must be a deliberate beta
promotion of the same foreground tick engine, not a semantic fork of the socket
stub.

The 2026-04-30 stay-afloat review keeps this boundary in place. Real Codex
dogfood proved route-scoped fallback from `codex:max-1#codex-max` quota
exhaustion to `codex:max-2#codex-max`, but it also exposed that runtime
permission/session ownership and automatic reauth are not solved by the current
daemon.

The 2026-05-03 usage-limit dogfood keeps the boundary in place as well. An
already-running provider-owned Codex session hit `You've hit your usage limit`
and no seamless daemon handoff occurred. Manual logout/login restored future
`stay-afloat next` readiness, but the daemon did not harden that active session
into a seamless fallback path.

`oauth-mux doctor runtime`, `oauth-mux route explain`, `oauth-mux route
select`, `oauth-mux repair-plan`, and `oauth-mux repair run` are the current
bridge between dogfooding evidence and future daemon work. They read local
runtime readiness and recorded liveness, then either diagnose account stores,
explain the route set, select the first currently usable route, print the next
non-mutating repair actions, or run one admitted repair action only after an
explicit confirmation flag.
`oauth-mux daemon repair-plan` is only a namespace alias for that same one-shot
planner; it does not start a background service, run probes, open browsers,
refresh credentials, or rewrite secret stores.

See `docs/spec/stay-afloat-runtime-daemon-plan-2026-04-30.md` for the runtime
gap analysis and `docs/spec/stay-afloat-supervisor-contract-2026-05-01.md` for
the portable foreground supervisor contract tracked by `TIN-859`. See
`docs/spec/stay-afloat-permission-broker-contract-2026-05-01.md` for how agents
and wrappers should handle `action.diagnostic_command` without promoting the
socket daemon.
See `docs/spec/background-stay-afloat-daemon-contract-2026-05-02.md` for the
`TIN-897` production-daemon contract and the distinction between prepared
fallback, supervised restart, current-process auth brokering, and true
per-request muxing.
See `docs/spec/codex-inplace-auth-broker-proof-2026-05-02.md` for the Codex
app-server auth-broker proof track, Linear `TIN-913` / GitHub `#125`.
See `docs/stay-afloat-wrappers.md` for beta wrapper recipes and soak checks
tracked by `TIN-899` / GitHub #105.
See `docs/spec/paid-cohort-soak-claim-policy-2026-05-03.md` for the paid
cohort soak and public-claim gate tracked by `TIN-895`.
See `docs/provider-repair-contracts.md` for the provider-mediated action
contract tracked by `TIN-900` / GitHub #106.

## Supervisor Contract

The stable stay-afloat contract is the foreground tick engine, not a platform
service manager and not the current socket stub:

```bash
oauth-mux stay-afloat --once --json
oauth-mux stay-afloat --loop --iterations <n> --interval-ms <ms> --json
oauth-mux stay-afloat --once --execute --json
oauth-mux stay-afloat handoffs --json
```

`oauth-mux daemon tick` is the lower-level alias for wrapper authors. It shares
the same planner/executor as `stay-afloat`.

`oauth-mux daemon run/start/stop/status` remains experimental socket plumbing.
It can report a local Unix socket status, but it does not host the stay-afloat
loop, perform automatic repair, or define production daemon semantics. This is
the final TIN-867 decision for the current release line.
Homebrew services, systemd user units, launchd plists, cron, Windows Services,
containers, and CI wrappers must preserve the foreground command contract
rather than introducing separate behavior.
`oauth-mux daemon status --json` reports this boundary directly with
`contract:"experimental_socket_stub"`, `production_supported:false`,
`hosts_stay_afloat:false`, and `wrapper_contract:"foreground_tick"`. It also
includes the latest redacted stay-afloat tick snapshot under `stay_afloat` when
one exists, so wrappers can inspect prepared fallback state without treating
the socket stub as the production supervisor. The sibling
`stay_afloat_snapshot` object reports whether that snapshot is present,
parseable, when it was last ticked, its age in seconds, the 300 second staleness
threshold, active-loop correlation, and a fresh/stale reason. Wrappers should
treat stale, missing, empty, malformed, or `before_current_loop` snapshots as
evidence to run or wait for a new foreground tick instead of trusting an old
prepared-fallback claim.
That snapshot includes `claim.level`. `prepared_fallback` means the next
mediated launch can select an account; it does not mean an already-running
harness process will be hot-swapped. The same claim object keeps
`current_process_hotswap:false`, `supervised_restart:false`, and
`per_request_muxing:false` until a specific wrapper, restart path, auth broker,
proxy, or in-agent adapter proves those stronger levels.

## Allowed Now

- `oauth-mux daemon run` as the foreground primitive for any future wrapper.
- `oauth-mux doctor runtime` for no-spend local runtime/session diagnostics,
  including profile-scoped route readiness checks.
- `oauth-mux route explain` for no-spend route-state explanation.
- `oauth-mux route select` for no-spend route choice from recorded evidence.
- `oauth-mux repair-plan` for non-mutating stay-afloat action planning.
- `oauth-mux repair run` for one explicit, confirmed repair command.
- `oauth-mux daemon repair-plan` as a compatibility alias for the same
  one-shot planner.
- `oauth-mux daemon status --json` for local inspection and machine-readable
  socket-daemon contract metadata.
- `oauth-mux daemon events --json` for the redacted repair-run event log. This
  reads local state and does not require a daemon process. The same stream also
  carries redacted `token_refresh` events for refresh admission/writeback
  outcomes.
- `oauth-mux stay-afloat handoffs --json` for the filtered pending queue of
  user-mediated daemon handoffs, such as upstream CLI login commands that must
  not run silently in the background. `oauth-mux daemon handoffs --json` is the
  lower-level alias. `--all` keeps the historical handoff events visible after
  later route evidence clears a pending prompt.
- `oauth-mux stay-afloat handoff ack --provider <provider> --account <account>
  [--profile <profile>] [--capability <capability>] --json` to record that a
  pending user-mediated repair was seen without clearing it.
- `oauth-mux stay-afloat handoff clear --provider <provider> --account
  <account> [--profile <profile>] [--capability <capability>] --json` to
  explicitly dismiss a stale pending handoff.
- `oauth-mux stay-afloat --once --json` for one portable, policy-gated
  daemon-shaped planning pass. `oauth-mux daemon tick --once --json` is the
  lower-level alias. Without `--execute`, it reports `executed:false` and does
  not run probes, repair commands, or mutation.
- `oauth-mux stay-afloat --once --execute --json` as the beta execution
  boundary. It runs at most one admitted non-interactive action per tick,
  re-reads route state afterward, and queues interactive reauth as a redacted
  `daemon_handoff` event instead of running it silently. Repeated ticks report
  an existing handoff as pending rather than appending duplicate events.
- `oauth-mux stay-afloat refresh --profile <profile> --capability <capability>
  --json` as the named one-shot execute tick for refreshing route evidence
  after a user-mediated upstream login.
- `oauth-mux stay-afloat --loop --iterations <n> --interval-ms <ms> --json`
  for a bounded foreground loop. It re-reads local health/runtime state each
  tick and remains service-manager agnostic. Route ticks expose
  `next_tick_after` plus `schedule_reason`, and the summary exposes the
  earliest `next_tick_after` plus `next_tick_reason`, so wrappers can back off
  without inventing separate scheduler semantics. The built-in loop also uses
  that earliest wake-up hint when sleeping between ticks, bounded by
  `--interval-ms`; the hint does not admit provider-spend probes, interactive
  auth, or mutation by itself.
- `oauth-mux daemon tick --loop --iterations <n> --interval-ms <ms> --json`
  as the lower-level wrapper-author spelling for the same bounded foreground
  loop.
- `oauth-mux stay-afloat supervise --max-restarts <n>
  --restart-on-exit-code <code> -- <command>` as the beta wrapper-owned restart
  path. It can claim `supervised_restart:true` only after oauth-mux spawned the
  child, observed the configured exit code, and restarted on another selectable
  route. It does not promote the socket daemon or claim current-process
  hot-swap.
- `oauth-mux stay-afloat supervise --restart-on-codex-usage-limit -- <command>`
  as a Codex-specific instrumentation path for wrapper-owned sessions. It
  captures child output, classifies the native usage-limit screen without
  printing the captured text, records route health as quota-exhausted, appends a
  redacted `stay_afloat_supervise` event, and then restarts on the next
  selectable route. This still requires oauth-mux to own the child process
  boundary.
- `claim.level:"prepared_fallback"` in `stay-afloat` / `daemon tick` JSON and
  in the latest `daemon status --json` snapshot when a route is selectable.
  Wrappers should pair that with the emitted `claim.launch_argv` and should not
  infer current-process hot-swap or per-request muxing. They should also read
  `resilience.spare_fallback_ready` / `claim.single_route_at_risk`: a selected
  route without a spare fallback is afloat for the next launch, but not
  resilient to another immediate quota/rate-limit failure. For Codex routes,
  broker-owned session, `route explain`, and `stay-afloat` surfaces expose the
  same explicit choices: revalidate exhausted routes, enroll another account, or
  wait for reset. JSON clients read `resilience_actions`; text output prints the
  matching `next:` hint.
- `oauth-mux daemon run --stay-afloat --profile <profile> --capability
  <capability>` as the first opt-in beta host for the same tick engine. It
  reports `stay_afloat_loop.hosted:true` plus the hosted selector, cadence, and
  execution mode while running, but `production_supported:false` and
  `hosts_stay_afloat:false` remain in status until soak and wrapper proof
  promote the daemon product surface.
- Account-scoped advisory locks during confirmed `repair run`, reported back as
  `repair_in_progress` by runtime-aware route planning.
- Config-level daemon admission policy for route planning. The default admits
  only `free_local` and `free_command` budgets; provider calls, provider-spend,
  interactive auth, and mutation remain refused unless explicitly configured.
- Local experimentation with daemon socket/status behavior.
- Secret-backend writeback classification in route/runtime/repair JSON. This
  tells operators whether a route is `readonly`, `replace_file`,
  `command_write`, `keychain_write`, `sops_write`, or `unsupported`, and whether
  oauth-mux automatic refresh writeback is admitted for that provider/account.
- Atomic file replacement for admitted `replace_file` OAuth refresh backends.
  This is provider-ownership-gated and does not apply to Codex or other
  upstream-CLI-owned stores.
- Future manual QA where daemon activity is bounded and visible.

## Not Allowed Yet

- Unbounded background polling of live provider probes.
- Automatic subscription-spending checks without explicit daemon policy.
- Silent token refresh for providers whose refresh semantics are owned by an
  upstream CLI.
- Silent execution of interactive repair-plan commands.
- Any release gate that depends on a long-running daemon.
- Treating `systemctl`, `launchctl`, Homebrew services, cron, or Windows
  Services as part of the core product contract.
- Presenting `oauth-mux daemon run/start` as the production stay-afloat daemon
  in the current product line.

## Promotion Criteria

The daemon can become a supported operator feature when:

1. provider refresh ownership is documented per provider;
2. credential writeback is explicit per secret backend;
3. refresh-token rotation and token age semantics are tested;
4. runtime permission failures are classified separately from OAuth failures;
5. refresh and probe budgets are configurable;
6. every background action records redacted evidence;
7. stop/status behavior is reliable on macOS and Linux;
8. Windows behavior is either implemented or explicitly unsupported in package
   docs;
9. live-provider QA covers timeout, auth failure, quota exhaustion, and
   transient rate-limit behavior.

The stronger "seamless muxing" claim also requires a mediation point. A
background daemon can keep route state and reauth handoffs warm, but it cannot
hot-swap credentials already loaded into an upstream harness process unless
that harness supports live reload, auth brokering, supervised restart,
proxying, or an oauth-mux-aware in-agent adapter. Until that proof exists,
user-facing copy should describe prepared fallback for the next mediated
action, not transparent replacement of the current process. The supervised
restart path is tracked in
`docs/spec/supervised-harness-restart-contract-2026-05-02.md`; it must remain a
separate wrapper-owned process claim, not a daemon status inference. The Codex
app-server auth-broker proof is tracked in
`docs/spec/codex-inplace-auth-broker-proof-2026-05-02.md` under Linear
`TIN-913` / GitHub `#125`; it is a
provider-specific current-process proof target, not a generic daemon claim.

Until then, user and agent onboarding should use one-shot commands:

```bash
oauth-mux discover --json
oauth-mux codex canary
oauth-mux doctor runtime --json
oauth-mux doctor runtime --profile <profile> --capability <capability> --json
oauth-mux route explain --profile <profile> --capability <capability> --json
oauth-mux route select --profile <profile> --capability <capability> --json
oauth-mux probe --profile <profile> --capability <capability> --json
oauth-mux repair-plan --profile <profile> --capability <capability> --json
oauth-mux repair run --profile <profile> --capability <capability> --json
oauth-mux stay-afloat --loop --iterations 2 --interval-ms 0 --profile <profile> --capability <capability> --json
oauth-mux stay-afloat refresh --profile <profile> --capability <capability> --json
oauth-mux daemon events --json
oauth-mux exec --profile <profile> --capability <capability> -- <command>
```
