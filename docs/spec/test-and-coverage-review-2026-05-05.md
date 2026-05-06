# Test, Coverage, Architecture, and Story Review
Date: 2026-05-05
Status: current-main assessment; not a product contract.

Anchor: `docs/spec/broker-mcp-contract-2026-05-03.md`.
Codex adapter contract: `docs/spec/codex-adapter-contract-2026-05-03.md`.

This review replaces the stale quarry-branch assessment from
`/Users/jess/git/oauth-mux-broker`. It describes current `main` through
`954d673` (`Whoohoo brokered Codex resume`), after route-health truthing,
Codex quarry smokes, expired-quota revalidation state, restart-claim demotion,
managed resume UX work, request-framing fixes, and same-account child-refresh
preservation.

## Product Bar

The only product success metric is Level 3 or better from the broker
contract: `oauth-mux <harness>` runs the harness, the active account
exhausts quota, another credited account is substituted in place, the
harness process is not restarted, and the user is not prompted.

Everything below Level 3 is evidence or diagnostic scaffolding.
`prepared_fallback`, managed launches, route warming, restart-shaped
flags, and synthetic smokes are not success.

## Current Evidence Stack

`just check-local` currently runs:

- `zig build test` and `zig build`.
- Config validation for every `examples/*.config.json`.
- `scripts/e2e-local.sh`.
- `scripts/first-run-e2e.sh`.
- `scripts/stay-afloat-wrapper-doc-smoke.sh`.
- `scripts/smoke-broker.sh`.
- `scripts/smoke-codex-acceptance.sh`.
- `scripts/smoke-codex-concurrent-sessions.sh`.
- `scripts/smoke-codex-child-refresh.sh`.
- `scripts/smoke-codex-tier-insufficient.sh`.
- `scripts/smoke-codex-all-exhausted.sh`.
- `scripts/smoke-codex-401-propagation.sh`.
- `scripts/smoke-codex-cassette-replay.sh`.

Validation status for the current resume/proxy slice: focused local gates have
passed (`zig build test`, `zig build`, `smoke-codex-cli-ux`,
`smoke-codex-acceptance`, and `smoke-codex-child-refresh`). A full
`just check-local` should be rerun before merge/release claims when this review
changes implementation.

Repo-wide Zig test inventory is broad (`rg '^test "' src` finds 306
in-file tests). The broker/Codex-adapter subset is materially covered
by in-file tests plus seven shell smokes.

The shell smoke suite covers these adapter stories:

- `smoke-broker`: 22 assertions. Broker MCP method composition:
  handshake, account listing, selection, materialization, quota
  observation, swap, and status.
- `smoke-codex-acceptance`: 20 assertions. Synthetic Codex A-to-B
  swap: account A succeeds, then returns `usage_limit_reached`; oauth-mux
  buffers that 429, marks A exhausted, retries the same request with B, and
  the stub Codex child sees only 200s in one stable child PID.
- `smoke-codex-concurrent-sessions`: 16 assertions. Per-session
  `CODEX_HOME` overlays prevent the old account-local `config.toml`
  clobber race.
- `smoke-codex-child-refresh`: 12 assertions. Codex child-refresh for the
  same account is preserved by the proxy, preventing stale materialized-token
  loops after a native Codex refresh.
- `smoke-codex-tier-insufficient`: 11 assertions.
  `usage_not_included` is classified as `tier_insufficient`; no swap.
- `smoke-codex-all-exhausted`: 12 assertions. All accounts exhausted returns
  a clean no-account-selectable failure after same-turn retry is unavailable.
- `smoke-codex-401-propagation`: 13 assertions. Upstream 401 is left
  for Codex's own refresh path; oauth-mux does not prematurely kill the
  route.
- `smoke-codex-cassette-replay`: 12 assertions. Captured-flow JSON can
  be replayed by `(method, path)` with diagnostic misses.

## Live Route Truth

As of 2026-05-05 15:37 EDT, no-spend route surfaces report:

- `codex-max` selected route: `max-1`.
- Selectable fallbacks: `max-2`, `max-3`, and `max-4`.
- `selectable_broker_routes:4`.
- `selectable_fallback_routes:3`.
- `spare_fallback_ready:true`.
- `single_route_at_risk:false`.

That unblocks fallback capacity for TIN-951 / GitHub #177. It does not
prove Level 3, because no provider-originated quota event was observed
inside a live `oauth-mux codex` session during that check.

## What Current Main Proves

- The broker MCP core can select accounts, materialize Codex credential
  tuples, observe quota, swap accounts, and report status in-process.
- The Codex adapter/proxy skeleton can run synthetic in-session flows
  without restarting its child process.
- The managed Codex frame can resume a real existing canonical Codex session
  and proxy normal live `responses` turns successfully.
- The proxy can preserve a same-account Codex-refreshed bearer instead of
  forcing stale oauth-mux materialized credentials.
- Route-health state now distinguishes expired reset windows as
  `revalidation_needed` until explicit provider revalidation refreshes
  truth.
- Restart-shaped surfaces are diagnostic-only. `supervised_restart` is
  no longer emitted in claim JSON, and legacy restart aliases report
  `compatibility_classification_only`.
- Real wire capture and replay tooling exists, but only synthetic replay
  data is checked in.

## What Current Main Does Not Prove

- Live provider-originated Level 3 account swap.
- Live invisible same-turn recovery where Codex never sees a visible
  `usage_limit_reached` failure when a fallback account is selectable.
- Same-thread continuity across account swap.
- Mid-turn recovery.
- Bare `codex` plus a separate background oauth-mux daemon seamlessly
  swapping account state.
- Real `chatgpt.com/backend-api/codex` cassette shapes for normal 200,
  401, 429 `usage_limit_reached`, WebSocket upgrade, or compact/memory
  endpoints.
- Claude, Cursor, Pi, or any non-Codex harness adapter.

## Architecture Decisions Worth Keeping Honest

1. **Broker MCP plus harness adapters is still the right frame.**
   Codex is the first adapter, not the whole product.
2. **Synthetic swap evidence is structural, not live evidence.**
   It is valuable because it pins the intended state machine, but it
   must not be labeled as Level 3.
3. **The Codex path depends on wire interposition.** Codex's 401 path
   can refresh; quota is a 429 and must be observed at the wire layer.
4. **The current 429 implementation has synthetic same-turn retry, not live
   provider proof.** It buffers a quota 429, marks account A exhausted, elects
   account B, drops `x-codex-turn-state`, and retries the same request before
   writing to Codex. The remaining risk is whether real `chatgpt.com` quota
   events and thread state behave like the synthetic model.
5. **The current child/proxy topology is the user-facing near path.**
   `oauth-mux codex` owns the mediation point. Bare `codex` with a
   background daemon remains a harder future sidecar problem.
6. **Restart diagnostics should keep shrinking.** They are useful for
   incident capture, not for product claims.

## Next Gates

1. Capture real Codex wire cassettes and live evidence for the same-turn 429
   path:
   - provider-originated `A -> 429 usage_limit_reached -> immediate B -> 200`;
   - assert the live Codex process does not receive a visible 429 when B
     succeeds;
   - assert one stable child PID, redacted status frames, and no restart
     language.
2. Keep extending the deterministic test ladder around that work:
   - Zig unit/PBT for response classification and swap state-machine
     invariants;
   - shell e2e for proxy behavior and CLI/session authority;
   - cassette replay for real wire-shape drift;
   - hosted CI before public claims.
3. Run the live TIN-951 acceptance only when the operator is ready to
   spend and has a credible way to observe provider-originated quota
   exhaustion in an active `oauth-mux codex` session.
4. Run TIN-950 / GitHub #176 capture for at least one normal 200 turn.
   Capture 401 and 429 only when safely available. Commit only reviewed,
   scrubbed, fixture-sized JSON.
5. Keep quarry work as quarry. The stale branch still has useful policy
   and review ideas, but main already supersedes much of its source diff.
6. Keep `docs/policy/tos-posture-2026-05-05.md` current before public
   promotion. Do not market account rotation as unlimited usage or quota
   evasion.
7. Start the Claude adapter only after Codex Level 3 is recorded or the
   Codex blocker is explicitly parked.

## Definition of Done for This Review

This review is complete when it is linked from the broker contract and
kept subordinate to that contract. It should be updated or replaced
whenever the evidence stack changes materially, especially after real
cassette capture or live Level 3 acceptance.
