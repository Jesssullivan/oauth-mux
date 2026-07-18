# Keepalive service units (launchd / systemd user)

Status: the macOS launchd path is live-proven on released v0.1.14: start,
five-account Claude refresh, kill/respawn, and throttle behavior are recorded in
`docs/evidence/keepalive-service-residency-20260704T161515Z/` (#444). The Linux
systemd-user path remains lint-level only. Service units are refresh/observation
support substrate, not the v0.2 per-session broker proxy; see the current
six-week plan and authority map.

These units wrap the shipped foreground tick engine:

    oauth-mux keepalive --iterations 100000 --interval-ms 60000 --json

They are wrappers, not core semantics (`docs/daemon-boundary.md`): the loop
is always bounded by `--iterations`; the service manager owns residency by
restarting the process on exit. They intentionally do NOT exec the
experimental `oauth-mux daemon` socket stub.

## Install (explicit, never automatic)

Nothing in `zig build`, release packaging, or any installer enables these
units. Installation is a deliberate operator action:

    just keepalive-service-install     # macOS: LaunchAgent; Linux: systemd --user
    just keepalive-service-status
    just keepalive-service-uninstall

The install step resolves the absolute `oauth-mux` binary path
(`OMUX_BIN` override → `PATH` → `~/.local/bin` → `/usr/local/bin` →
`/opt/homebrew/bin` → `/usr/bin`), refuses to install if no runnable binary
is found, renders the template from `dist/launchd/` or `dist/systemd/`,
lints it, and only then loads/enables it. Note: the `keepalive` verb
requires a binary built from main after PR #417.
An explicit `OMUX_BIN` must resolve to a regular executable file; executable
directories and other non-regular filesystem objects are rejected by render,
verify, and install.

The contained resident service currently supports only the default omux path
domain. Render, verify, and install fail closed when any of `OMUX_CONFIG`,
`OMUX_CONFIG_DIR`, `OMUX_STATE_DIR`, `OMUX_RUNTIME_DIR`,
`OMUX_CODEX_STORE_ROOT`, `OMUX_CLAUDE_CONFIG_ROOT`, `XDG_CONFIG_HOME`,
`XDG_STATE_HOME`, `XDG_RUNTIME_DIR`, or `XDG_DATA_HOME` is set, including to an
empty value. The refusal names the variable but never reads or prints its value.
This prevents the foreground harness and resident service from using different
config, credential-store, quarantine, state, runtime, or flock domains. Custom
domains remain unsupported until setup can install and validate one explicit
path-domain manifest.

Rendered `HOME`, `USER`, and the macOS `gui/<uid>` target come from the
current process identity and OS account database through absolute system-tool
paths. Caller-supplied `HOME`, `USER`, and PATH-shadowed identity tools cannot
redirect service placement or change the LaunchAgent identity. Help and status
remain available with `HOME` and `USER` unset.

- macOS: `~/Library/LaunchAgents/dev.xoxd.omux.keepalive.plist`,
  label `dev.xoxd.omux.keepalive`, logs in `~/Library/Logs/oauth-mux/`.
- Linux: `~/.config/systemd/user/oauth-mux-keepalive.service`, logs in
  the user journal (`journalctl --user -u oauth-mux-keepalive`).

The units pin `PATH` to system directories only (`/usr/bin:/bin:/usr/sbin:/sbin`
in the plist; the systemd user manager's own default on Linux). The builtin
keychain backend is unaffected (`/usr/bin/security` is invoked by absolute
path), but a config-driven `command` secret backend that names a bare
executable (e.g. `op`, `pass`) will not resolve under the service even though
it works in your login shell — use absolute paths in config for
command-backend secret references.

On macOS, the LaunchAgent invokes `/usr/bin/env -i` and then supplies exactly
the validated `HOME`, `USER`, fixed `PATH`, and `NO_COLOR=1` assignments before
the resolved absolute `oauth-mux` binary and fixed keepalive arguments. It does
not use an `EnvironmentVariables` dictionary, so launchd's inherited environment
is discarded rather than forwarded to the resident process. On every platform,
rendering requires the complete LaunchAgent source to match the canonical
top-level dictionary. This rejects `Program`, `EnvironmentVariables`, duplicate
or entity-encoded keys, unknown assignments, noncanonical values, unresolved
markers, non-absolute HOME/executable values, XML/sed metacharacters, and an
executable path containing `=`. On Darwin, absolute `/usr/bin/plutil` must also
parse the rendered plist to the same effective dictionary; absence, parse
failure, or an effective-value mismatch fails closed.

Before install or uninstall changes the plist, `launchctl print` distinguishes a
loaded job from the launchctl absent-service status. A loaded job must boot out
successfully. Any other inspection or bootout error aborts: install does not
replace the plist, and uninstall preserves it. Status likewise reports
`service_loaded=false` only for the absent-service result, never for a generic
launchctl failure.

## What actually gets warmed (consent model)

Keepalive is consent-gated per account. Installing the service warms
nothing until the operator sets `allow_proactive_refresh: true` on specific
accounts in config (default false); the provider must also declare the
`proactive_refresh` grant (claude/codex builtins do). Accounts sharing one
OAuth identity are refused outright (family-revocation protection), and
accounts without readable credential expiry are skipped with a logged
warning. A pool with no eligible accounts drains harmlessly: the process
exits 0 and the service manager relaunches it on a 5-minute floor.

## Restart semantics (and why not `Restart=on-failure`)

`oauth-mux keepalive` exits 0 even when refreshes fail or the pool drains —
the JSON summary counters are the failure signal, exit 1 is reserved for
config-load errors. Residency therefore must not key off exit status:
launchd uses `KeepAlive=true` + `ThrottleInterval=300`; systemd uses
`Restart=always` + `RestartSec=300`.

## Logs and health

- One JSON summary line per process incarnation on stdout:
  `{"accounts":N,"ticks":N,"refreshed":N,"failed":N,"died":N,"transient":N,"quarantined":N,"drained":bool}`
- Diagnostics go to stderr (`NO_COLOR=1` is set in the unit environment).
- Redacted refresh events: `oauth-mux daemon events --json`.
- macOS service status emits only the fixed `service_label` and
  `service_loaded=true|false` fields; raw `launchctl print` output is discarded.
  This read-only path does not require `HOME` or `USER`.
- macOS log growth: launchd appends to the `StandardOutPath`/`StandardErrorPath`
  files and macOS never rotates custom files under `~/Library/Logs/` — a
  persistently failing account logs one warning per account per tick.
  Truncate periodically or add a `newsyslog.d` rule. journald on the systemd
  side rotates on its own.

## Guardrails (binding)

1. No credentials, tokens, or secret material in unit files or environment
   arguments — the binary reads credential stores/keychain live at runtime.
   `just keepalive-service-verify` enforces the complete macOS dictionary and
   scans both service units. Doctor reports a resident executable only when the
   installed plist independently passes the same complete dictionary semantics.
   Resident inspection is metadata-only: doctor hashes the selected file but
   never executes a plist-selected path. Invalid or unreadable containment is
   emitted as an explicit unhealthy, stale warning in JSON and text.
   The resident plist is opened nonblocking, classified, size-bounded, and read
   through one descriptor. The final target must be a regular file: a symlink
   resolving to a regular file is accepted, while a FIFO or symlink to a FIFO
   fails closed without waiting for a writer.
2. No sops-materialization of rotating OAuth material anywhere in this lane.
3. Units are operator-installed explicitly; never by build or packaging.
4. The nix/home-manager service module is out of scope here (TIN-1834,
   parked); packaging-SSOT emission of these units is TIN-2046.

## Offline validation

`just keepalive-service-verify` runs: canonical source validation on every host,
effective-dictionary validation through `/usr/bin/plutil` on macOS, static
section/key checks on the rendered systemd unit, verb assertion (`keepalive`,
never `stay-afloat`), and a credential-marker scan.
On macOS, `systemd-analyze verify` is unavailable; full systemd
verification is pending live Linux validation and is reported as such.

These unit-text checks and the synthetic containment smoke are source-only
defense-in-depth. They do not activate or restart a LaunchAgent, do not provide
live value-free process evidence, and do not authorize promotion. TIN-1759 and
Stage 4 of the v0.2 evaluation ladder remain explicitly open.
