# Keepalive warm-loop evidence — Stage 1 (refused-safely tick)

- Date (UTC): 2026-07-02T21:42:11Z → 2026-07-02T21:42:11Z
- Binary: oauth-mux 0.1.13 built from main @ 47ec4b8 (includes the TIN-2059
  in-process actor gate, PR #430) via `nix develop -c zig build`.
- Command (verbatim, no forcing, no config changes):
  `oauth-mux keepalive --once --json` against the operator's live config.
- Result (verbatim): `{"accounts":5,"ticks":1,"refreshed":0,"failed":4,"died":0,"drained":false}`, exit 0.

## What this run shows (capped at the captured output)

1. The warm loop enumerates the live pool on the post-gate binary and exits
   cleanly after one tick.
2. Every consent gate fired: all 4 warm candidates (claude:xoxd,
   claude:sulliwood, codex:max-3, codex:max-4) were refused writeback with
   `proactive_refresh_not_opted_in` — the live config has zero per-account
   opt-ins, so the `failed` counter records consent refusals, not network
   failures (see keepalive-once.stderr.log).
3. Expected-refusal fixtures FIRED: codex:default and codex:max-1 were
   excluded by the TIN-2113 shared-identity guard (family-revocation
   protection), logged verbatim.
4. gemini:default and vercel:default dropped at secret read (NotFound) —
   not pool members on this machine.
5. Zero mutation: pool-before.json and pool-after.json are BYTE-IDENTICAL
   (verified with diff); no credential store changed; snapshots contain no
   credential material (grep-verified before commit).

## What this run does NOT claim

- Not a soak (TIN-2057 remains open); not "keepalive proven".
- No live rotation was exercised — that requires per-account operator opt-in
  (`allow_proactive_refresh: true`), which is Stage 2 (dogfood fleet,
  operator-gated, see TIN-2057 2026-07-02 operator comment).
- No claim about service residency (TIN-1830 units are a separate lane).

Provenance: push-plan lane W1-6 (docs/plans/keepalive-push-2026-07-02.md),
TIN-2057 Stage 1, session 9925b2e2, 2026-07-02.
