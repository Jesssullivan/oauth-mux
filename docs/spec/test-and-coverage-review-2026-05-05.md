# Test, Coverage, Architecture, and Story Review
Date: 2026-05-05
Status: historical current-main assessment; not a product contract.

Anchor: `docs/spec/broker-mcp-contract-2026-05-03.md`.
Codex adapter contract: `docs/spec/codex-adapter-contract-2026-05-03.md`.

This review replaces the stale quarry-branch assessment from
`<local-quarry-worktree>`. It describes the 2026-05-05 `main` state through
`9cdf5a3` (`Add Codex dogfood status monitor helper (#209)`), after
route-health truthing, Codex quarry smokes, expired-quota revalidation state,
restart-claim demotion, managed resume UX work, request-framing fixes,
same-account child-refresh preservation, auth fallback chain summarization,
managed auth-health recording, and dogfood-9's live auth-continuity event
followed by failed live quota handoff. It is superseded for current Codex
quota-handoff evidence by
`docs/spec/codex-live-quota-handoff-evidence-2026-05-08.md`, and for current
route/test matrix truth by `docs/qa-handoff-matrix.md`.

## Product Bar

The only product success metric is Level 3 or better from the broker
contract: `oauth-mux <harness>` runs the harness, the active account
exhausts quota, another credited account is substituted in place, the
harness process is not restarted, and the user is not prompted.

Everything below Level 3 is evidence or diagnostic scaffolding.
`prepared_fallback`, managed launches, route warming, restart-shaped
flags, and synthetic smokes are not success.

## Current Evidence Stack

`just remote-check` is the proof gate for merge/release claims. It dispatches
the validation body to the GloriousFlywheel runner instead of asking developer
laptops to compile and test the repo. The underlying local body is still
`scripts/check-local.sh`; do not copy its full command list into specs. At a
high level it covers:

- `zig build test`, `zig build`, and config validation for every
  `examples/*.config.json`.
- Local first-run, stay-afloat, broker MCP, Codex managed CLI UX, synthetic
  handoff, concurrent-session, child-refresh, tier, all-exhausted, 401,
  cassette replay/review, status-summary, and tracker-comment smokes.

Run `just remote-check` before merge/release claims when this review changes
implementation or claim language. Local `just check-local` is for debugging only.

Repo-wide Zig test inventory is broad (`rg '^test "' src` finds 306
in-file tests). The broker/Codex-adapter subset is materially covered by
in-file tests plus the shell smoke chain in `scripts/check-local.sh`.

## Live Route Truth

Historical snapshots in this review explain why earlier work was opened or
closed. Current Codex route truth and account-state vocabulary live in
`docs/qa-handoff-matrix.md`; live provider runbook details live in
`docs/live-provider-qa.md`.

The 2026-05-08 installed-runtime artifacts proved managed load/resume quota
handoff. The 2026-05-09 engineered artifact proved the stricter managed-session
handoff shape after successful primary-route traffic. Same-thread semantics,
mid-turn streaming recovery, unmanaged bare-`codex` daemon handoff, and
non-Codex harness behavior remain separate proof lanes.

## Dogfood-9 Auth Continuity Plus Failed Quota Handoff

`dist/live-qa/managed-resume-dogfood-9/status.ndjson` is the strongest current
live managed-session artifact, but it is failed stay-afloat evidence, not a
successful quota handoff.

The run launched with `selected_account:"codex:max-1"` and
`session_authority:"canonical_bridge"`. The selected account returned
`401 auth_unauthorized`, oauth-mux retried the same buffered request through
`codex:max-2` and `codex:max-3`, and `codex:max-4` returned `200`. Subsequent
useful live `POST /responses` traffic continued through `codex:max-4`.

Later in the same artifact, `codex:max-4` returned provider-originated
`429 usage_limit_reached` / `quota_exhausted`, and oauth-mux reported
`proxy_same_turn_retry_unavailable` / `NoAccountSelectable` instead of
substituting another credited account. The correct summarizer verdict is
`quota_handoff_failed`; at the time, this kept TIN-916 / GitHub #131 and
TIN-951 / GitHub #177 open. Later May 8 and May 9 installed-runtime evidence
superseded that state for the managed Codex handoff claim; same-thread,
mid-turn streaming, unmanaged-daemon, non-Codex, and negative/permutation
lanes remain separate proof surfaces.

## 2026-05-08 Managed Load Quota Handoff

`<oauth-mux-state>/codex/status/managed-1778273610565.ndjson`
and `managed-1778271585359.ndjson` are installed-runtime managed Codex
artifacts, not repo-local wrapper runs. They show `codex:default` returning
provider-originated `429 usage_limit_reached` on `POST /responses`; oauth-mux
records the quota event, keeps the 429 from Codex, drops
`x-codex-turn-state`, retries the same request on `codex:max-2`, and receives
`status:200`.

The updated status oracle reports
`verdict:"successful_live_quota_handoff"` for these artifacts. This upgrades
the managed load/resume claim, but it does not close same-thread, mid-turn, or
bare unmanaged `codex` claims.

## 2026-05-09 Engineered Managed-Session Quota Handoff

`<oauth-mux-state>/codex/status/managed-1778362718969.ndjson` is an
installed-runtime managed Codex artifact from the low-weekly engineered burn.
It shows successful `codex:max-2` `responses` turns before
provider-originated `429 usage_limit_reached`; oauth-mux records quota, keeps
the 429 from Codex, drops `x-codex-turn-state`, retries on `codex:max-3`, and
receives `status:200`.

The reviewed proof bundle is
`docs/evidence/codex-engineered-quota-handoff-20260509/`. This closes the
engineered managed-session quota handoff shape. It does not close same-thread
continuity semantics, mid-turn streaming recovery, unmanaged bare-`codex`
daemon handoff, or non-Codex harness behavior.

## What Current Main Proves

- The broker MCP core can select accounts, materialize Codex credential
  tuples, observe quota, swap accounts, and report status in-process.
- The Codex adapter/proxy skeleton can run synthetic in-session flows
  without restarting its child process.
- The managed Codex frame can resume a real existing canonical Codex session
  and proxy normal live `responses` turns successfully.
- The managed Codex proxy can keep a real session afloat across selected-route
  auth failure by retrying the buffered request on a fallback account before
  Codex sees the 401.
- The managed Codex proxy can keep a real resume/load turn afloat across
  provider-originated `usage_limit_reached` by retrying the buffered request on
  a fallback account before Codex sees the 429.
- The managed Codex proxy can keep an engineered live session afloat after an
  initially successful primary route reaches provider-originated
  `usage_limit_reached`, by retrying the same buffered request on a fallback
  route that returns 200.
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
4. **The current 429 implementation has live managed Codex proof, not full
   same-thread proof.** It buffers a quota 429, marks account A exhausted,
   elects account B, drops `x-codex-turn-state`, and retries the same request
   before writing to Codex. Real `chatgpt.com` quota events have now passed
   that path both on load/resume and in the engineered 2026-05-09 managed
   session where the primary route returned successful traffic before
   exhaustion.
5. **The current child/proxy topology is the user-facing near path.**
   `oauth-mux codex` owns the mediation point. Bare `codex` with a
   background daemon remains a harder future sidecar problem.
6. **Restart diagnostics should keep shrinking.** They are useful for
   incident capture, not for product claims.

## Next Gates

1. Preserve the 2026-05-08 and 2026-05-09 installed-runtime same-turn 429
   evidence and turn it into deterministic regression coverage:
   - assert provider-originated A `429 usage_limit_reached`;
   - assert immediate B -> 200 and no visible 429 when B succeeds;
   - assert redacted status frames, terminal evidence, and no restart language.
2. Keep extending the deterministic test ladder around that work:
   - Zig unit/PBT for response classification and swap state-machine
     invariants;
   - shell e2e for proxy behavior and CLI/session authority;
   - cassette replay for real wire-shape drift;
   - hosted CI before public claims.
3. Run the next live acceptance only when the operator is ready to spend and
   has a credible way to preserve additional provider-originated quota
   permutations, such as all-fallbacks-exhausted, tier-insufficient fallback,
   reset repair, and mid-turn streaming cases.
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
