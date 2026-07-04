# Keepalive service residency — live proof (TIN-1830)

- Date (UTC): 2026-07-04T16:15:15Z → 2026-07-04T16:16:57Z+throttle
- Binary: the RELEASED v0.1.14, installed via the stranger lane
  (`install.sh` from the GitHub release resolved latest → v0.1.14 →
  `~/.local/bin/oauth-mux`; see stranger-install.log). Repo @ c7235c1 for the
  service templates/recipes only.

## Acceptance legs (original TIN-1830 charter) — all three proven

1. **Service starts**: `scripts/keepalive-service.sh install` (OMUX_BIN
   explicit) rendered, linted, placed, and loaded the LaunchAgent
   `dev.xoxd.omux.keepalive`; launchd state=running, PID 8410,
   properties `keepalive|runatload` (launchctl-state-initial.txt).
2. **Warms the pool**: first tick under launchd rotated the ENTIRE 5-account
   Claude fleet — five `token: refreshed successfully` events
   (first-ticks.err.log) — with every guard firing around them: TIN-2113
   shared-identity refusals (codex:default/max-1), not-opted-in refusals
   (codex:max-3/max-4), benign stub secret errors. First all-5 fleet rotation
   on record, and it happened under service residency on the shipped release.
3. **Restarts cleanly**: killed PID 8410 → launchd `spawn scheduled` →
   ThrottleInterval=300 honored (anti-thrash by design) → respawned as PID
   15658, state=running, post-respawn ticks flowing with no spurious
   re-rotation (fleet fresh) (restart-test.log).

## Honest bounds

- launchd (macOS) leg only; the systemd-user unit remains lint-level validated,
  live Linux proof pending.
- The TIN-1830 description ADDENDUM acceptance (doctor build_id/sha surfacing,
  stale-binary warning, PATH-shadow detection) is code work still OPEN — this
  dir proves the original charter, not the addendum.
- Not the TIN-2057 golden metric (Codex side remains opted out).

Provenance: session 9925b2e2, 2026-07-04, operator present (Jess + Fable
dogfood session on neo).
