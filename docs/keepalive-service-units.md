# Keepalive service units (launchd / systemd user)

Status: unit files lint-clean, install path implemented. **Not yet
live-proven** — the start → warm → restart evidence run is a separate,
operator-gated step and no "service proven" or "keepalive works" claim is
made by this document. Service units are substrate, per
`docs/plans/keepalive-push-2026-07-02.md` (W2-5 copy constraint).

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

- macOS: `~/Library/LaunchAgents/dev.xoxd.omux.keepalive.plist`,
  label `dev.xoxd.omux.keepalive`, logs in `~/Library/Logs/oauth-mux/`.
- Linux: `~/.config/systemd/user/oauth-mux-keepalive.service`, logs in
  the user journal (`journalctl --user -u oauth-mux-keepalive`).

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
  `{"accounts":N,"ticks":N,"refreshed":N,"failed":N,"died":N,"drained":bool}`
- Diagnostics go to stderr (`NO_COLOR=1` is set in the unit environment).
- Redacted refresh events: `oauth-mux daemon events --json`.

## Guardrails (binding)

1. No credentials, tokens, or secret material in unit files or environment
   blocks — the binary reads credential stores/keychain live at runtime.
   `just keepalive-service-verify` greps enforce this.
2. No sops-materialization of rotating OAuth material anywhere in this lane.
3. Units are operator-installed explicitly; never by build or packaging.
4. The nix/home-manager service module is out of scope here (TIN-1834,
   parked); packaging-SSOT emission of these units is TIN-2046.

## Offline validation

`just keepalive-service-verify` runs: `plutil -lint` on the rendered plist
(macOS), static section/key checks on the rendered systemd unit, verb
assertion (`keepalive`, never `stay-afloat`), and a credential-marker scan.
On macOS, `systemd-analyze verify` is unavailable; full systemd
verification is pending live Linux validation and is reported as such.
