# Broker Worktree Quarry Todo
Date: 2026-05-05
Status: local todo and quarry map; not a product contract.

Anchor docs:

- `AGENTS.md`
- `docs/spec/broker-mcp-contract-2026-05-03.md`
- `docs/spec/codex-adapter-contract-2026-05-03.md`
- `docs/spec/harness-session-authority-bridge-2026-05-05.md`
- `docs/spec/codex-wire-evidence-2026-05-03.md`
- `docs/spec/codex-managed-resume-ux-refactor-2026-05-06.md`

## Product Bar

The product succeeds only when the user runs `oauth-mux <harness>`, the
active subscription account exhausts, and another credited account is
substituted in place without restart, logout, manual resume, prompt, or
provider-owned session relaunch.

Everything below is in service of that bar. Route warming, restart,
prepared fallback, and synthetic smokes are evidence or diagnostics only.

## Current Live State

Observed on 2026-05-05 around 15:37 EDT, then updated after brokered-resume
dogfood on 2026-05-06, dogfood-9 auth-continuity plus failed-quota evidence
on 2026-05-07, and installed-runtime managed quota handoff evidence on
2026-05-08:

- Repository: clean on `main`, synced with `origin/main` at `9cdf5a3`
  (`Add Codex dogfood status monitor helper (#209)`) during this checkpoint.
- Selected live `codex-max` route: `max-1`.
- Spend-gated exhausted-route revalidation after the reset window found
  `max-1`, `max-2`, and `max-3` available again; `max-4` was already
  selectable.
- `broker-session-plan` reports `routes_total:4`,
  `selectable_broker_routes:4`, `selectable_fallback_routes:3`,
  `spare_fallback_ready:true`, and `single_route_at_risk:false`.
- `route explain` agrees: `max-1` selected; `max-2`, `max-3`, and
  `max-4` selectable fallbacks.

This unblocked fallback capacity for Level 3. Dogfood-9 then showed the
route-health view was stale: provider-originated `usage_limit_reached` did
occur inside a live `oauth-mux codex` session, and oauth-mux still had no
selectable fallback when `codex:max-4` exhausted. The 2026-05-08 installed
runtime artifacts then proved the repaired load/resume path: `codex:default`
exhausted, oauth-mux recorded quota, dropped `x-codex-turn-state`, retried the
same request on `codex:max-2`, and got `status:200`.

The brokered-resume dogfood proved a separate prerequisite:

- `oauth-mux codex --profile codex-max resume <session-id>` re-entered a
  canonical Codex session through the managed frame.
- Status evidence reported `session_authority:"canonical_bridge"`,
  `auth_authority:"mux_owned_overlay"`, and `managed_config:"mux_owned_overlay"`.
- Live `POST /backend-api/codex/responses` turns returned `status:200` through
  the oauth-mux proxy after the request-framing and same-account child-refresh
  fixes.
- `dist/live-qa/managed-resume-dogfood-5/status.ndjson` proved brokered
  resume and ordinary selected-route 200s.
- `dist/live-qa/managed-resume-dogfood-9/status.ndjson` proved live managed
  auth-continuity fallback, then failed the quota stay-afloat bar: it launched
  on `codex:max-1`, retried selected-route `401 auth_unauthorized` through
  `max-2` and `max-3`, continued through `codex:max-4`, then observed a real
  `429 usage_limit_reached` on `codex:max-4` and ended with no selectable
  fallback.
- `<oauth-mux-state>/codex/status/managed-1778273610565.ndjson`
  and `managed-1778271585359.ndjson` proved installed-runtime live quota
  handoff on managed resume/load from `codex:default` to `codex:max-2`.
- `<oauth-mux-state>/codex/status/managed-1778362718969.ndjson` proved the
  engineered managed-session handoff shape: successful `codex:max-2` traffic,
  provider-originated `usage_limit_reached`, same-request retry to
  `codex:max-3`, and fallback `status:200`.

That is meaningful UX/architecture progress and real managed load/resume
quota-handoff evidence. It still must not be broadened into same-thread,
mid-turn, unmanaged `codex`, or non-Codex harness claims. Use
`docs/spec/codex-live-acceptance-checklist-2026-05-08.md` for the managed
Codex closure criteria.

## Mainline Reality

Already merged on main:

- Broker MCP core.
- Codex adapter/proxy skeleton.
- Per-session `CODEX_HOME` overlay; account-local `config.toml` is not
  clobbered by adapter sessions.
- Synthetic Codex acceptance smoke: account A succeeds, then returns
  `usage_limit_reached`; oauth-mux buffers that 429, marks A exhausted,
  retries the same request with B, and the stub Codex child sees only 200s in
  one stable child PID.
- Brokered Codex resume through canonical session authority; the managed frame
  can now resume a real existing Codex session and proxy normal provider turns.
- Brokered auth-continuity dogfood: selected-route 401s can be hidden from
  Codex by same-turn retry across fallback accounts, with subsequent useful
  traffic on `codex:max-4`; the same artifact later failed quota handoff when
  `codex:max-4` exhausted quota.
- Installed-runtime managed quota handoff: selected-route
  `usage_limit_reached` can be hidden from Codex by same-turn retry to a
  fallback account, with successful `responses` traffic on `codex:max-2`.
- Engineered installed-runtime managed quota handoff: after successful
  primary-route traffic, provider-originated `usage_limit_reached` can be
  hidden from Codex by same-turn retry to a fallback account, with successful
  `responses` traffic on `codex:max-3`.
- Same-account child auth refresh preservation; oauth-mux no longer overwrites
  a Codex-refreshed bearer for the same account with stale materialized route
  credentials.
- Cassette capture/replay tooling; real operator capture data is still
  pending.
- `--json-status-file` artifact path, so oauth-mux status frames do not
  corrupt real Codex stderr/stdout.
- Unit and property tests for broker/session ids, credential handle
  parsing, header forwarding, quota classification, and per-session
  overlay behavior.

Not yet proven:

- Same-thread continuity across account swap.
- Mid-turn recovery.
- Bare `codex` plus a separate background oauth-mux daemon seamlessly
  handing off account state.
- Additional live chooser dogfood with multiple real Codex sessions remains
  useful UX evidence, but the regression guard now exists: `oauth-mux codex
  resume` forwards native chooser mode, validates canonical session authority
  before child spawn, and fails redacted if the managed overlay cannot expose
  the required authority entries.

## Quarry Worktree

Worktree:

```text
<local-quarry-worktree>  jess/broker-mcp-codex-adapter
```

State at review time:

- `ahead 33, behind 5`.
- Clean worktree.
- Not a merge candidate.
- Treat as a quarry for small reviewed slices only.

The branch is stale relative to main and would regress important merged
work if merged wholesale. In particular, it would remove the current
cassette replay smoke, weaken status artifact behavior, and reintroduce
shared account-local `CODEX_HOME` assumptions that main already replaced
with per-session overlays.

## Quarry Classification

### Cherry-pick, With Adaptation

These are valuable but must be applied onto current main, not merged from
the branch as-is:

1. `scripts/smoke-codex-tier-insufficient.sh`
   - Goal: prove `usage_not_included` is classified as
     `tier_insufficient` and does not trigger account swap.
   - Status: adapted onto main with main's redaction/status-file
     conventions.
   - Added as `just smoke-codex-tier-insufficient`.

2. `scripts/smoke-codex-all-exhausted.sh`
   - Goal: prove all accounts exhausted returns a clean
     `proxy_no_account_selectable` / 503 path without restart or loop.
   - Status: adapted onto main with current claim and status semantics.
   - Added as `just smoke-codex-all-exhausted`.

3. `scripts/smoke-codex-401-propagation.sh`
   - Goal: pin the important behavior that upstream 401 is propagated so
     Codex's own refresh path can run; oauth-mux must not mark the account
     dead before Codex gets a chance to refresh.
   - Status: adapted onto main and verified against the current
     `wire_proxy.zig` behavior and status artifact path.
   - Added as `just smoke-codex-401-propagation`.

4. Concurrent-session smoke concept
   - The quarry script documents the old `config.toml` clobber race.
   - Main already fixed that with per-session overlays.
   - Status: adapted onto current main as
     `just smoke-codex-concurrent-sessions`.
   - The expected result is stronger than the quarry version: both
     concurrent sessions get their own proxy traffic, both child PIDs
     remain stable, proxy ports are distinct, and account-local config
     files are not mutated.

5. `docs/spec/test-and-coverage-review-2026-05-03.md`
   - Valuable as an assessment, but stale in counts and conclusions.
   - Status: rewritten from current main as
     `docs/spec/test-and-coverage-review-2026-05-05.md`.
   - The rewrite explicitly separates structural synthetic evidence,
     cassette replay readiness, live route readiness, and the missing
     live Level 3 evidence.

6. `docs/policy/tos-posture-2026-05-03.md`
   - Policy posture is needed before public promotion.
   - Status: rewritten from current official OpenAI sources as
     `docs/policy/tos-posture-2026-05-05.md`.
   - The rewrite avoids "unlimited" / bypass framing and says not to
     link from first-run or public promotion copy until Level 3 is
     live-proven and the posture is re-reviewed.

### Already Absorbed or Superseded

- Broker MCP core and Codex adapter skeleton are already on main.
- Per-session `CODEX_HOME` overlay is already on main.
- Status-file artifact path is already on main and is stronger than the
  quarry branch.
- Cassette replay tooling is already on main; the quarry branch's deletion
  of `scripts/smoke-codex-cassette-replay.sh` is wrong.
- Header forwarding, request parsing, quota classification, and PBT
  coverage are partially already on main; cherry-pick only missing tests
  after checking current `zig build test` inventory.

### Reject

- Any source diff that reverts `--json-status-file`.
- Any source diff that prints `CODEX_HOME`, credential paths, token
  material, raw JWT bodies, or upstream account ids in normal output.
- Any source diff that promotes synthetic mock swap evidence to
  `next_turn_seamless`.
- Any docs or code that describe restart/supervision as a product success
  path.
- Any direct deletion of main's cassette replay smoke.
- Any shared account-local `config.toml` mutation model for adapter
  sessions.

## Dead Code / Stale Surface Watchlist

These need review before public promotion:

- `stay-afloat launch`, `codex managed`, and supervised wrapper language:
  keep as diagnostic/Level 1 surfaces only; do not let docs frame them as
  stay-afloat success.
- JSON claim flag soup (`supervised_restart`, `current_process_hotswap`,
  `per_request_muxing`, `unmanaged_tui_hotswap`): migrate toward the broker
  contract claim ladder where possible.
- `broker-*` proof commands: keep as diagnostic regression surfaces, not
  product UX.
- Expired quota health: TIN-973 / GitHub #183 landed in PR #185
  (`562d478`). Past reset windows now surface as
  `revalidation_needed` instead of indistinct active
  `quota_exhausted`, and routes remain non-selectable until explicit
  provider revalidation refreshes truth.
- Linear/GitHub tracker drift: TIN-941 / GitHub #172 and TIN-948 /
  GitHub #174 were confirmed satisfied by PR #178 (`9a8aea6`) and PR #179
  (`c7c6512`), then closed/marked Done during this hygiene pass.
- TIN-949 / GitHub #175 is intentionally still open: PR #180 (`3a3da0f`)
  fixed the per-session overlay implementation, but the stronger
  concurrent-session smoke remains pending until this hygiene branch lands.

## Architectural Uncertainties

1. Live Level 3 acceptance
   - Need a second selectable `codex-max` route after spend-gated
     revalidation.
   - Then run TIN-951 and record artifacts.

2. Real wire capture
   - `docs/spec/codex-wire-evidence-2026-05-03.md` still has
     `OPERATOR-CONFIRM` fields.
   - Need one real capture with normal turn, 401 if safely triggerable,
     and quota exhaustion when available.

3. 429 recovery mode
   - Main now proves synthetic same-turn A-to-B retry behavior.
   - The proxy buffers `429 usage_limit_reached`, marks account A exhausted,
     elects B, drops `x-codex-turn-state`, retries the same request, and only
     writes B's response to Codex when B succeeds.
   - Do not claim live seamless stay-afloat until provider-originated evidence
     confirms the same no-visible-429 sequence against real `chatgpt.com`.

4. Daemon-attached broker mode
   - In-process broker is good enough for current adapter smokes.
   - Multi-session, multi-harness route truth wants daemon-attached state
     later.

5. Session authority bridge
   - `oauth-mux codex run -- ... resume <id>` must see the same canonical
     Codex session authority as bare `codex` while keeping auth/config
     mux-owned.
   - Full-store copies are rejected; the current adapter uses a
     bridge/reference model per
     `docs/spec/harness-session-authority-bridge-2026-05-05.md`.
   - Explicit live managed-frame resume now works. Continue daily-use checks
     for `resume --last`, native chooser behavior, and redacted writeback
     evidence per `docs/spec/codex-managed-resume-ux-refactor-2026-05-06.md`.

6. Bare `codex` path
   - The aspirational background daemon plus bare `codex` remains harder
   than `oauth-mux codex`.
   - Treat as future adapter/sidecar research, not the current acceptance
     gate.

7. Claude adapter
   - Important to prove broker contract generality.
   - Start only after Codex Level 3 acceptance or after the Codex blocker is
     explicitly parked.

## Local Todo Order

1. Keep main clean and preserve all four selectable `codex-max` routes.
2. Capture real Codex wire cassettes for TIN-950 / GitHub #176:
   normal 200 flow first, then 401 and 429 only when safely available.
3. Run live Level 3 acceptance for TIN-951 only when the operator is ready to
   spend and there is a realistic way to observe provider-originated quota
   exhaustion in an active `oauth-mux codex` session.
4. Keep demoting route-warming/restart surfaces from product language.
5. Keep extending the test ladder: Zig unit/PBT, shell e2e, cassette replay,
   live redacted artifacts, and hosted CI.
6. Start the Claude adapter only after the Codex Level 3 proof is recorded
   or explicitly parked.
7. Re-run `just check-local` after each code/test slice.
8. Treat dogfood-9 as failed live quota handoff evidence: it burned
   `codex:max-4` after auth fallback and did not substitute another route.

## Hygiene Pass Notes

2026-05-06:

- PR/local commit `5161b23` changed the Codex proxy from next-request-only
  quota recovery to synthetic same-turn retry:
  `A -> 429 usage_limit_reached -> mark A exhausted -> elect B -> drop
  x-codex-turn-state -> retry same request -> B 200`.
- `scripts/smoke-codex-acceptance.sh` now asserts the stub Codex child sees
  only 200s when a fallback account succeeds; the original quota 429 is logged
  as `delivered_to_codex:false`.
- Negative-path guards now assert no same-turn retry on
  `usage_not_included` or 401, and all-accounts-exhausted reports
  `proxy_same_turn_retry_unavailable` plus a clean no-account-selectable path.
- Full `just check-local` passed after the proxy and smoke updates.
- No-spend live route readiness, run with normal local filesystem access:
  selected `codex:max-1`; selectable fallbacks `max-2`, `max-3`, and `max-4`;
  `selectable_broker_routes:4`, `selectable_fallback_routes:3`,
  `spare_fallback_ready:true`, `single_route_at_risk:false`.
- GitHub MCP connector issue-comment writes for #131, #176, and #177 failed
  with `403 Resource not accessible by integration`; the connector needs
  issue-comment permission before it can be trusted for tracker writes.
- Local `gh` posting succeeded after ignoring a stale `GH_TOKEN` environment
  variable and using the valid keyring/CLI auth. Comments posted:
  #131 `4384946494`, #177 `4384947088`, #176 `4384947627`.
- 2026-05-06 managed-session check: this does not appear to be an
  `oauth-mux` Codex proxy failure. The managed session exports
  `OMUX_ACTIVE_PROVIDER=codex`, `OMUX_ACTIVE_ACCOUNT=max-1`, and
  `OMUX_ACTIVE_PROFILE=codex-max`, but no process-wide `HTTP_PROXY` /
  `HTTPS_PROXY`. The Codex adapter writes a per-session `config.toml`
  provider override for `/backend-api/codex`; it does not intercept GitHub
  connector requests. Local `gh auth status` reports a repo-scoped token with
  write-capable scopes, while the Apps connector identity is independent and
  can read identity but fails issue-comment writes. Treat connector writes as
  a GitHub App permission/installation problem until proven otherwise.
- GitHub #198 tracks the permission fix. Until the connector can write issue
  comments, use `scripts/github-tracker-comment.sh` as the local `gh` fallback;
  it dry-runs auth/body checks and refuses obvious unredacted token shapes.
- Supersession after the 2026-05-09 installed-runtime proof: the engineered
  managed-session exhaustion handoff has been captured. Remaining gates are
  same-thread semantics, mid-turn recovery, unmanaged daemon handoff, and
  negative/permutation coverage.

2026-05-05:

- Added the tier-insufficient, all-exhausted, and 401-propagation Codex
  negative-path smokes to the repo-managed local gate.
- Closed GitHub #172 / #174 and marked Linear TIN-941 / TIN-948 Done
  after confirming their merged PR coverage.
- Left GitHub #175 / TIN-949 open and annotated the remaining
  concurrent-session smoke acceptance gap.
- Added the current-main concurrent-session smoke to the repo-managed
  local gate.
- `just check-local` passed with the new smokes included.
- Spend-gated exhausted-route revalidation after the reset window restored
  all four `codex-max` routes to selectable state.
- PR #185 (`562d478`) landed expired-quota `revalidation_needed`
  semantics and closed GitHub #183 / Linear TIN-973.
- PR #186 (`2858810`) removed the retired `supervised_restart` claim
  field.
- PR #187 (`59c2f69`) reports legacy restart-shaped aliases as
  compatibility classification only.
- Rewrote the stale quarry test/coverage review from current main as
  `docs/spec/test-and-coverage-review-2026-05-05.md` and linked it from
  the broker contract as a descriptive assessment.
- Rewrote the quarry ToS posture into
  `docs/policy/tos-posture-2026-05-05.md` from current official OpenAI
  sources, with public-promotion links gated until Level 3 is live-proven.
