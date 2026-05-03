# Stay-Afloat Wrapper Recipes

Status: beta operator recipes for the supervised stay-afloat loop and
wrapper-owned child restart.

These recipes make the current daemon beta dogfoodable without changing the
public product claim. The loop can keep route-state evidence warm and queue
user-mediated repair handoffs, but it does not hot-swap credentials inside an
unmanaged already-running upstream harness process.

The next stronger claim is wrapper-mediated supervised restart, tracked in
`docs/spec/supervised-harness-restart-contract-2026-05-02.md`. The first slice
is now `stay-afloat supervise`: a parent-wrapper command that spawns a child
instead of using `execve`, observes the child exit, and can restart on another
selected route when the operator gives a typed exit-code classifier.

Codex now also has a separate app-server auth-broker proof track:
`docs/spec/codex-inplace-auth-broker-proof-2026-05-02.md`. That path may become
current-process auth switching for Codex sessions launched under oauth-mux
app-server mediation. It is not the same claim as these generic wrapper recipes.

## Product Truth

The supported contract is still the portable tick engine:

```bash
oauth-mux stay-afloat next --profile codex-max --capability codex-max --json
oauth-mux stay-afloat launch --profile codex-max --capability codex-max -- codex
oauth-mux codex managed-plan --profile codex-max --capability codex-max --json
oauth-mux codex managed --profile codex-max --capability codex-max -- --no-alt-screen
oauth-mux codex managed --profile codex-max --capability codex-max --resume-last --include-non-interactive
oauth-mux stay-afloat supervise --profile codex-max --capability codex-max --max-restarts 1 --restart-on-exit-code 42 -- codex
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

Use `stay-afloat supervise --max-restarts <n> --restart-on-exit-code <code>
-- <command>` when oauth-mux should own the child process boundary. The generic
path restarts only when the child exits with the configured code, skips the
already-attempted route for that supervise run, and emits redacted JSON/text
evidence with `claim.supervised_restart:true` only after an actual wrapper-owned
restart occurred.

For Codex dogfood, add `--restart-on-codex-usage-limit`. That path captures
child stdout/stderr, classifies known Codex usage-limit text, records the
selected route as quota-exhausted with `last_probe.source:"supervised_child_output"`,
appends a redacted `stay_afloat_supervise` event, and restarts on the next
selectable route. Captured output is not printed; JSON reports byte counts and
the redacted `output_classification:"codex_usage_limit"` value only. This is
still wrapper-owned restart mediation, not same-thread recovery or unmanaged
TUI hot-swap.

The beta supervised daemon host wraps that same engine:

```bash
oauth-mux daemon run --stay-afloat --profile codex-max --capability codex-max --interval-ms 60000
oauth-mux daemon supervise --profile codex-max --capability codex-max --interval-ms 60000
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
  "contract": "experimental_supervised_loop",
  "production_supported": false,
  "hosts_stay_afloat": false,
  "stay_afloat_loop": {
    "hosted": true,
    "mode": "stay_afloat_supervisor",
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
  "transport": "foreground_supervised_loop",
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
      "supervised_restart": false,
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

## Smoke And Soak

Use a bounded loop first. It should write a redacted snapshot and exit without
leaving a daemon pid behind:

```bash
oauth-mux daemon supervise --profile codex-max --capability codex-max --iterations 3 --interval-ms 500
oauth-mux daemon status --json
```

Then run the long-lived beta host:

```bash
oauth-mux daemon supervise --profile codex-max --capability codex-max --interval-ms 60000
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
- `contract:"experimental_supervised_loop"` while the beta host is active.
- `stay_afloat_loop.hosted:true` while the beta host is active.
- `stay_afloat_loop.selector` matches the profile/provider/account/capability
  you meant to supervise.
- `stay_afloat_loop.interval_ms` and `stay_afloat_loop.execution_mode` match the
  cadence and admission boundary you meant to run.
- `transport:"foreground_supervised_loop"` and `socket:null`.
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
exec oauth-mux daemon supervise --profile codex-max --capability codex-max --interval-ms 60000
```

For a bounded proof in a PR or release lane:

```bash
oauth-mux daemon supervise --profile codex-max --capability codex-max --iterations 3 --interval-ms 500
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
    <string>supervise</string>
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
ExecStart=/usr/local/bin/oauth-mux daemon supervise --profile codex-max --capability codex-max --interval-ms 60000
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

The current supervised daemon pid/status host is not implemented on Windows.
Windows packages should not claim `oauth-mux daemon supervise` as supported
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
oauth-mux daemon supervise --profile codex-max --capability codex-max --iterations 3 --interval-ms 500
oauth-mux daemon status --json
```

Container entrypoint shape:

```bash
exec oauth-mux daemon supervise --profile codex-max --capability codex-max --interval-ms 60000
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
