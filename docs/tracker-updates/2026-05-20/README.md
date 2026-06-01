# Tracker Update Drafts - 2026-05-20

Status: local drafts only. Do not post to GitHub or Linear without explicit
operator approval.

## Shared Current Truth

- BrokenPipe/network-blip regression work is locally implemented and verified.
  Downstream Codex/client socket closes are now distinct from upstream provider
  interruptions in the managed Codex proxy path. Upstream partial `200` streams
  that EOF before the promised `Content-Length` are treated as provider
  interruption, not successful route health.
- Local gates passed, refreshed at 2026-05-21 03:20 UTC:
  `python3 -m py_compile` for Codex stubs, `bash -n` for the provider-degraded
  smoke, `just smoke-codex-provider-degraded-local`, `just test`,
  `just check-local`, and `git diff --check`.
- Current installed diagnostic route truth from the 2026-05-21 02:57 UTC
  post-repair refresh: active binary is user-local `oauth-mux 0.1.9`; native
  Codex resolves outside oauth-mux; four `codex-max` route stores are
  runtime/broker ready; `codex:max-3` is selected; `max-4` is a live selectable
  fallback; `max-1` and `max-2` remain blocked as `unrecorded`.
- Current resilience is `session_start_ready:true`, `fallback_ready:true`,
  `single_route_at_risk:false`.
- Current cassette/live gate: a real cassette capture can proceed only after a
  just-in-time diagnostic snapshot reconfirms spare fallback capacity and the
  operator explicitly approves any live provider-spend capture.
- Daemon remains non-production: `status:"not_running"`,
  `contract:"experimental_socket_stub"`, `hosts_stay_afloat:false`; foreground
  tick snapshots are observational only even when fresh.

## GitHub #176 / Linear TIN-950 - Real Codex Wire Cassettes

Draft:

> 2026-05-20 local update, not a closure claim:
>
> The BrokenPipe/network-blip regression is now covered locally: downstream
> Codex/client disconnects are classified as `proxy_client_disconnected` and do
> not poison route health or same-turn retry, while upstream/provider
> interruptions remain provider-degraded evidence and do not retry after a
> partial stream reaches Codex. The regression also covers short `Content-Length`
> EOF on a partial upstream `200`, so that does not persist false successful
> route health. Local gates are green, including
> `just smoke-codex-provider-degraded-local`, `just test`, and
> `just check-local`.
>
> Real cassette capture is still open. The 2026-05-21 post-repair diagnostic
> refresh shows user-local `oauth-mux 0.1.9`, `codex:max-3` selected, and
> `max-4` available as a live selectable fallback. `max-1` and `max-2` remain
> `unrecorded`. Current resilience is `fallback_ready:true` and
> `single_route_at_risk:false`, but the next cassette attempt should still do a
> just-in-time diagnostic snapshot and get explicit operator approval for any live
> provider-spend capture.
>
> Tracker hygiene note: Linear `TIN-950` is marked Done, but this GitHub issue
> remains the active public gate for real Codex wire cassette acceptance. Treat
> that as a mismatch until a real scrubbed cassette fixture lands or Linear is
> clarified.

Completion metric before closing:

- At least one scrubbed real Codex `200` streaming cassette is committed.
- `usage_limit_reached`, `usage_not_included`, `401`, and all-fallbacks
  exhausted are captured or explicitly marked not observed.
- Replay smoke fails diagnostically on shape drift and is included in CI-safe
  local validation.

## GitHub #212 / Linear TIN-1079 - Codex Quota Matrix

Draft:

> 2026-05-21 post-repair diagnostic snapshot: `codex:max-3#codex-max` is selected
> and `max-4` is a live selectable fallback. `max-1` and `max-2` are
> runtime/broker ready but still blocked as `unrecorded`, so the profile is
> afloat with one spare fallback:
> `session_start_ready:true`, `fallback_ready:true`,
> `single_route_at_risk:false`.
>
> This means the negative permutation matrix can move out of the single-route
> risk block, but release-grade evidence still requires a just-in-time diagnostic
> refresh and explicit approval for provider-spend cases. API-credit
> false-positive, all-fallbacks-exhausted, tier-insufficient, and reset-window
> repair remain the priority negative permutations.

## GitHub #67 - Broker Daemon And Adapter Contract

Draft:

> BrokenPipe/network-blip hardening improves the managed Codex broker-owned
> proxy path without expanding daemon claims. Downstream client disconnects no
> longer look like provider degradation, and upstream stream interruptions are
> recorded as provider-degraded without retrying after partial delivery.
>
> Daemon truth remains unchanged: current `daemon status` is not running,
> experimental socket stub only, and `hosts_stay_afloat:false`. Foreground tick
> snapshots must not be cited as unmanaged daemon hot-swap evidence.

## GitHub #163 / Linear TIN-938 - Codex Remote App-Server Sidecar

Draft:

> Keep this queued behind the BrokenPipe/cassette path. The first acceptable
> next step is still a diagnostic sidecar smoke proving loopback transport,
> remote auth token handling, connection ordering, and TUI attachment. No live
> sidecar spend proof or managed interactive UX claim should be made until a
> separate acceptance run exists.

## GitHub #68 / Linear TIN-736 - Provider Proof Beyond Codex

Draft:

> Keep non-Codex proof secondary until the Codex reference adapter has stable
> negative/cassette evidence. The next non-Codex provider should be admitted by
> the provider-authoring checklist with fixture-backed positive and negative
> proof. No non-Codex stay-afloat, background daemon, or universal provider
> claim should be made from schema-modeled support alone.
