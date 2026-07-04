# Keepalive rotation-under-loop evidence — 5-Claude fleet (Stage 3)

- Binary: `/Users/jess/.local/bin/oauth-mux` 0.1.13, built + installed from main
  @ 35abbb8 (post-#438/#439). sha256 in `binary-sha256.txt`. Rebuilt this session
  specifically because the earlier dogfood ran a stale v0.1.13 (release-staleness
  lesson, TIN-2409/TIN-1830).
- Config: operator live config, 5 Claude accounts opted in
  (xoxd/sulliwood/columbari/coye/lmux), `personal` opted out, no forcing, no
  config edits during the run.

## What this proves

**Proactive credential rotation firing INSIDE the running keepalive loop** — not a
hand-run `--once` tick. Run A (`keepalive --iterations 26 --interval-ms 300000`,
started 2026-07-03T21:39:16Z) refreshed **two Claude accounts on its
proactive tick**: `runA-interrupted.stderr.log` shows 2× `token: refreshed
successfully` immediately after the TIN-2113 shared-identity refusals, i.e. the
loop's scheduler found xoxd + sulliwood due (past ~75% token lifetime) and rotated
them under the daemon loop. Both accounts are `ready` in the after-snapshot with
fresh tokens; every other account byte-identical.

Run A was interrupted by session churn at 2026-07-03T22:50:11Z (a
foreground child dies with its wrapper — itself the argument for TIN-1830 service
residency). It was relaunched **detached** (double-fork, own session) as run B.

## Run B — 20-tick stability soak (`runB-keepalive.json`)

```json
{"accounts":8,"ticks":20,"refreshed":0,"failed":14,"died":2,"drained":false}
```
Span: 2026-07-03T22:50:11Z → 2026-07-03T23:56:42Z,
exit 0.

- `refreshed:0` is expected and honest: xoxd + sulliwood were already rotated in
  run A (no longer due); columbari/coye/lmux did not cross their proactive-due
  line within this window. The loop correctly refreshed nothing that wasn't due.
- `died:2` is an **ephemeral in-run counter, NOT a persisted death**: the
  before/after `accounts list` snapshots show all 10 accounts `ready` with zero
  credential-field mutation (`pool-before.json` vs `pool-after.json`). Attributed
  to transient probe classification on the non-account stubs (`gemini:default`,
  `vercel:default` — `secret: NotFound`); it did not durably mark any account dead.
- `failed:14` = the two NotFound stubs across ticks. No enrolled account failed.

## Honest bounds — what this does NOT prove

- NOT all-5 simultaneous rotation: only the 2 accounts that came due (xoxd,
  sulliwood) rotated. columbari/coye/lmux rotation awaits their next due window.
- NOT the TIN-2057 golden metric: that needs 2×Claude + **2×Codex** rotating; the
  Codex side (max-3/max-4) is opted OUT here. This is the Claude-side
  rotation-under-loop leg only.
- NOT service residency (TIN-1830): this was a hand-launched detached process, not
  `just keepalive-service-install`. The session-churn kill of run A is exactly the
  failure mode service units fix.
- `died:2` warrants a glance if it recurs on a clean fleet — filed as an
  observation, not a defect (no persisted impact here).

Provenance: session 9925b2e2, 2026-07-03. TIN-2057 Stage 3 (Claude rotation-under-loop).
