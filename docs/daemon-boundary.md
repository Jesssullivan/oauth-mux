# Daemon Boundary

The daemon exists, but it is not a production dependency yet.

## Current Decision

Keep daemon usage optional until provider-specific refresh semantics are proven
for each OAuth-backed harness. The default production path remains explicit
selection, explicit probe, env injection, and exec handoff.

The 2026-04-30 stay-afloat review keeps this boundary in place. Real Codex
dogfood proved route-scoped fallback from `codex:max-1#codex-max` quota
exhaustion to `codex:max-2#codex-max`, but it also exposed that runtime
permission/session ownership and automatic reauth are not solved by the current
daemon.

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

See `docs/spec/stay-afloat-runtime-daemon-plan-2026-04-30.md`.

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
- `oauth-mux daemon status --json` for local inspection.
- `oauth-mux daemon events --json` for the redacted repair-run event log. This
  reads local state and does not require a daemon process.
- Account-scoped advisory locks during confirmed `repair run`, reported back as
  `repair_in_progress` by runtime-aware route planning.
- Local experimentation with daemon socket/status behavior.
- Future manual QA where daemon activity is bounded and visible.

## Not Allowed Yet

- Background polling of live provider probes.
- Automatic subscription-spending checks.
- Silent token refresh for providers whose refresh semantics are owned by an
  upstream CLI.
- Automatic execution of repair-plan commands without an explicit foreground
  user command and confirmation flag.
- Any release gate that depends on a long-running daemon.
- Treating `systemctl`, `launchctl`, Homebrew services, cron, or Windows
  Services as part of the core product contract.

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
oauth-mux daemon events --json
oauth-mux exec --profile <profile> --capability <capability> -- <command>
```
