# Stay-Afloat Wrapper Recipes — Diagnostic / Level 1–2 Only

Status: diagnostic and route-warming recipes. **NOT THE PRODUCT.**

> The product entrypoint is `oauth-mux codex` (and future
> `oauth-mux <harness>` adapters) per
> `docs/spec/broker-mcp-contract-2026-05-03.md` and
> `docs/spec/codex-adapter-contract-2026-05-03.md`. Those adapters target
> Level 3 (`next_turn_seamless`) — same harness process, no restart, no
> prompt, account A exhausts and account B continues.
>
> Everything below is Level 1 (`prepared_fallback`) or Level 2
> (`broker_owned` for adapter-launched sessions, or
> `observed_child_process` for `stay-afloat observe`). It does not hit
> the success metric, and it must not be framed as if it does.

These recipes make the current daemon beta dogfoodable. The loop can keep
route-state evidence warm and queue user-mediated repair handoffs. It does
not hot-swap credentials inside an unmanaged already-running upstream
harness process — the broker adapters do.

Wrapper-mediated restart is not a stay-afloat claim of any level.
`stay-afloat observe` is a parent-wrapper diagnostic command: it spawns a
child instead of using `execve`, observes typed failures, records route
evidence, and stops. It does not relaunch a fallback child. Restart is not
acceptable seamless stay-afloat behavior; the broker adapters in
`oauth-mux codex` are the in-place swap path.
The historical wrapper contract lives at
`docs/spec/observed-child-diagnostic-contract-2026-05-02.md`; it is
diagnostic failure-observation history, not a product restart plan, and
the supervised-restart-named file at
`docs/spec/supervised-harness-restart-contract-2026-05-02.md` has been
demoted to an obsolescence pointer.

Codex's in-process auth-broker work is tracked at
`docs/spec/codex-inplace-auth-broker-proof-2026-05-02.md` and
`docs/spec/codex-adapter-contract-2026-05-03.md`. The adapter spec is the
load-bearing one; the in-place proof spec is the source-evidence record.

## Product Truth

The supported contract is still the portable tick engine:

```bash
oauth-mux stay-afloat next --profile codex-max --capability codex-max --json
oauth-mux stay-afloat launch --profile codex-max --capability codex-max -- codex
oauth-mux codex managed-plan --profile codex-max --capability codex-max --json
oauth-mux codex managed --profile codex-max --capability codex-max -- --no-alt-screen
oauth-mux codex managed --profile codex-max --capability codex-max --resume-last --include-non-interactive
oauth-mux stay-afloat observe --profile codex-max --capability codex-max --classify-codex-usage-limit --stream-capture -- codex
oauth-mux stay-afloat --loop --iterations 2 --interval-ms 0 --profile codex-max --capability codex-max --json
oauth-mux daemon tick --loop --iterations 2 --interval-ms 0 --profile codex-max --capability codex-max --json
```

Use `stay-afloat next --json` before launching a harness from an agent or
wrapper. It does not spend provider calls or mutate auth state; it either
returns an exact `oauth-mux exec` argv for the selected route or returns the
typed repair/handoff action to mediate first.

Use `stay-afloat launch -- <command>` when the wrapper should actually start a
new harness session. It runs the same route preflight, pins the selected account
for `oauth-mux exec`, and refuses to run the target when repair or user handoff
is needed. Because the delegated exec path still validates token and runtime
state before startup, launch can refresh route evidence and try the next
selectable account when a route that looked selectable at preflight is
reclassified before the target starts. If no selectable account remains, it
prints the refreshed mediation text and exits nonzero.

For native Codex, prefer `codex managed` over a bare `stay-afloat launch -- codex`
when you want the invocation and resume semantics to be explicit. It uses the
same selected route boundary, injects the selected route-local `CODEX_HOME`,
and can forward `resume --last --include-non-interactive` for sessions created
in that store. Explicit `--resume <id>` is preflighted against that selected
store before native Codex starts; missing ids fail with a redacted diagnostic
instead of launching the wrong account. It still cannot import or rescue an
unmanaged already-running Codex session.

Use `stay-afloat observe --classify-exit-code <code>
-- <command>` when oauth-mux should observe the child process boundary. The
legacy restart-shaped flags now admit classification only; the command does
not relaunch the child or attempt fallback execution. Its claim remains
diagnostic: `acceptable_seamless_behavior:false`, and the retired
`supervised_restart` claim field is omitted rather than carried as a negative
product promise.
If an operator still uses `stay-afloat supervise`, `--max-restarts`,
`--restart-on-exit-code`, or `--restart-on-codex-usage-limit`, JSON reports
`legacy_restart_aliases_used:true` with
`legacy_restart_aliases_effect:"compatibility_classification_only"`.

For Codex dogfood, add `--classify-codex-usage-limit`. That path captures
child stdout/stderr, classifies known Codex usage-limit text, records the
selected route as quota-exhausted with `last_probe.source:"observed_child_output"`,
appends a redacted `stay_afloat_observe` event, and stops. Captured output is
not printed; JSON reports byte counts and the redacted
`output_classification:"codex_usage_limit"` value only. This is wrapper-owned
failure observation, not same-thread recovery, unmanaged TUI hot-swap, or an
acceptable product handoff.

For interactive dogfood where the operator must see the child output while the
classifier still runs, add `--stream-capture` with
`--classify-codex-usage-limit`. This tees child output back to the terminal
while retaining bounded classifier buffers. With `--json`, child output is
streamed to stderr so stdout remains parseable JSON. This is a streaming pipe
path, not a PTY/raw-terminal claim.

The beta foreground loop host wraps that same engine:

```bash
oauth-mux daemon run --stay-afloat --profile codex-max --capability codex-max --interval-ms 60000
oauth-mux daemon loop --profile codex-max --capability codex-max --interval-ms 60000
```

The loop uses route scheduler hints when sleeping: the earliest
`next_tick_after` in the tick summary can wake the next pass before the fixed
cadence, while `--interval-ms` remains the maximum sleep. This keeps quota reset,
handoff, and runtime repair rechecks responsive without granting extra provider
budget or mutation rights.

While the beta loop is running, `oauth-mux daemon status --json` should report
fields shaped like:

```json
{
  "status": "running",
  "contract": "experimental_foreground_tick_loop",
  "production_supported": false,
  "hosts_stay_afloat": false,
  "stay_afloat_loop": {
    "hosted": true,
    "mode": "stay_afloat_tick_loop",
    "selector": {
      "profile": "codex-max",
      "provider": null,
      "account": null,
      "capability": "codex-max"
    },
    "once": false,
    "iterations": 4294967295,
    "interval_ms": 60000,
    "execution_mode": "execute"
  },
  "transport": "foreground_tick_loop",
  "socket": null,
  "stay_afloat_snapshot": {
    "present": true,
    "parseable": true,
    "last_tick_at": 1777752000,
    "age_seconds": 2,
    "loop_started_at": 1777751998,
    "current_loop_observed": true,
    "stale_after_seconds": 300,
    "stale": false,
    "reason": "fresh"
  },
  "stay_afloat": {
    "claim": {
      "level": "prepared_fallback",
      "current_process_hotswap": false,
      "per_request_muxing": false
    }
  }
}
```

`production_supported:false` and `hosts_stay_afloat:false` are intentional. The
beta loop is useful for dogfooding, wrapper integration, and soak proof, but it
is not yet the production background daemon claim tracked by GitHub #67.
`claim.level:"prepared_fallback"` means the next mediated launch can select an
account through `stay-afloat launch`; it does not claim current-process
hot-swap, supervised restart, or per-request muxing.
Observed usage-limit dogfood on 2026-05-03 confirmed that an unmanaged
already-running Codex session does not seamlessly hand off through this daemon
surface. The wrapper recipes should be treated as route-warming and launch
mediation, not active-session rescue.

The only success metric for true Codex stay-afloat is stricter: a normal
running `codex` process with oauth-mux in the background must survive quota
exhaustion by moving the active session to another credited account without
logout, manual resume, restart, or lost thread. None of the wrapper recipes
claim that behavior.

## Smoke And Soak

Use a bounded loop first. It should write a redacted snapshot and exit without
leaving a daemon pid behind:

```bash
oauth-mux daemon loop --profile codex-max --capability codex-max --iterations 3 --interval-ms 500
oauth-mux daemon status --json
```

Then run the long-lived beta host:

```bash
oauth-mux daemon loop --profile codex-max --capability codex-max --interval-ms 60000
```

Inspect it from another shell:

```bash
oauth-mux daemon status --json
oauth-mux daemon handoffs --json
oauth-mux daemon events --json
```

Stop it explicitly:

```bash
oauth-mux daemon stop
oauth-mux daemon status --json
```

Good soak evidence includes:

- `status:"running"` while the wrapper is active.
- `contract:"experimental_foreground_tick_loop"` while the beta host is active.
- `stay_afloat_loop.hosted:true` while the beta host is active.
- `stay_afloat_loop.selector` matches the profile/provider/account/capability
  you meant to run.
- `stay_afloat_loop.interval_ms` and `stay_afloat_loop.execution_mode` match the
  cadence and admission boundary you meant to run.
- `transport:"foreground_tick_loop"` and `socket:null`.
- A redacted `stay_afloat` snapshot with selected route, fallback, repair, or
  handoff state.
- `stay_afloat_snapshot.present:true`, `parseable:true`, `stale:false`, and
  `current_loop_observed:true` while the beta loop is active. Missing, empty,
  malformed, stale, or `before_current_loop` metadata means the wrapper should
  run or wait for a fresh foreground tick before trusting prepared fallback
  state.
- `status:"not_running"` after `oauth-mux daemon stop`.
- No hidden browser/device auth.
- No provider-spend probes unless the operator opted into a spend-capable
  command or daemon admission policy.

## Plain Shell

Use this when a user, CI job, terminal multiplexer, or external supervisor owns
process lifetime:

```bash
exec oauth-mux daemon loop --profile codex-max --capability codex-max --interval-ms 60000
```

For a bounded proof in a PR or release lane:

```bash
oauth-mux daemon loop --profile codex-max --capability codex-max --iterations 3 --interval-ms 500
oauth-mux daemon status --json
```

Rollback is just:

```bash
oauth-mux daemon stop
```

## macOS Launchd

Create `~/Library/LaunchAgents/dev.xoxd.omux.codex-max.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>dev.xoxd.omux.codex-max</string>
  <key>ProgramArguments</key>
  <array>
    <string>/opt/homebrew/bin/oauth-mux</string>
    <string>daemon</string>
    <string>loop</string>
    <string>--profile</string>
    <string>codex-max</string>
    <string>--capability</string>
    <string>codex-max</string>
    <string>--interval-ms</string>
    <string>60000</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/tmp/omux-codex-max.out.log</string>
  <key>StandardErrorPath</key>
  <string>/tmp/omux-codex-max.err.log</string>
</dict>
</plist>
```

Start and inspect:

```bash
launchctl bootstrap "gui/$(id -u)" ~/Library/LaunchAgents/dev.xoxd.omux.codex-max.plist
launchctl kickstart -k "gui/$(id -u)/dev.xoxd.omux.codex-max"
oauth-mux daemon status --json
```

Rollback:

```bash
launchctl bootout "gui/$(id -u)" ~/Library/LaunchAgents/dev.xoxd.omux.codex-max.plist
oauth-mux daemon stop
rm -f ~/Library/LaunchAgents/dev.xoxd.omux.codex-max.plist
```

## Linux Systemd User Unit

This is an optional wrapper recipe, not the oauth-mux core contract. Put this
in `~/.config/systemd/user/omux-codex-max.service`:

```ini
[Unit]
Description=oauth-mux Codex Max stay-afloat beta loop
Documentation=https://github.com/Jesssullivan/oauth-mux/issues/67

[Service]
Type=simple
ExecStart=/usr/local/bin/oauth-mux daemon loop --profile codex-max --capability codex-max --interval-ms 60000
Restart=on-failure
RestartSec=15s

[Install]
WantedBy=default.target
```

Start and inspect:

```bash
systemctl --user daemon-reload
systemctl --user enable --now omux-codex-max.service
oauth-mux daemon status --json
```

Rollback:

```bash
systemctl --user disable --now omux-codex-max.service
oauth-mux daemon stop
rm -f ~/.config/systemd/user/omux-codex-max.service
systemctl --user daemon-reload
```

Do not require systemd for adoption. Containers, SSH hosts, and minimal Linux
machines can use the plain shell contract instead.

## Windows Current Lane

The current foreground loop daemon pid/status host is not implemented on Windows.
Windows packages should not claim `oauth-mux daemon loop` as supported
until stop/status/process control is implemented there.

For now, use the portable foreground loop under Task Scheduler, PowerShell,
WinSW, NSSM, or another operator-owned supervisor:

```powershell
oauth-mux.exe stay-afloat --loop --profile codex-max --capability codex-max --interval-ms 60000 --json
```

Task Scheduler shape:

```powershell
$Action = New-ScheduledTaskAction `
  -Execute "oauth-mux.exe" `
  -Argument "stay-afloat --loop --profile codex-max --capability codex-max --interval-ms 60000 --json"
$Trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "omux-codex-max" -Action $Action -Trigger $Trigger
```

Rollback:

```powershell
Unregister-ScheduledTask -TaskName "omux-codex-max" -Confirm:$false
```

Windows promotion needs a separate implementation or wrapper contract for
process status, stop behavior, and redacted snapshot inspection.

## Container Or CI

Use bounded loops in CI and long-lived foreground loops in containers. Avoid
backgrounding inside the container entrypoint; let the container runtime own the
process:

```bash
oauth-mux daemon loop --profile codex-max --capability codex-max --iterations 3 --interval-ms 500
oauth-mux daemon status --json
```

Container entrypoint shape:

```bash
exec oauth-mux daemon loop --profile codex-max --capability codex-max --interval-ms 60000
```

Rollback is container or job termination plus an explicit status check in the
same state/runtime namespace:

```bash
oauth-mux daemon stop
oauth-mux daemon status --json
```

## Dogfood Notes

For Codex, a good dogfood run intentionally includes at least one exhausted
account and one available account. The expected outcome is prepared fallback for
the next mediated action, not hot replacement of credentials inside an
unmanaged current Codex process. For app-server broker dogfood, use the Codex
broker proof spec and keep auth-recovery proof separate from quota-exhaustion
proof.

For Claude and Figma, do not claim parity until provider-mediated repair
contracts distinguish quota exhaustion, auth death, scope insufficiency, local
store permission failures, and upstream-login-required states. That work is
tracked separately by GitHub #106 / Linear TIN-900 and summarized in
`docs/provider-repair-contracts.md`.
