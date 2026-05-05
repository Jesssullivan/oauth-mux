# Broker Worktree Quarry Todo
Date: 2026-05-05
Status: local todo and quarry map; not a product contract.

Anchor docs:

- `AGENTS.md`
- `docs/spec/broker-mcp-contract-2026-05-03.md`
- `docs/spec/codex-adapter-contract-2026-05-03.md`
- `docs/spec/codex-wire-evidence-2026-05-03.md`

## Product Bar

The product succeeds only when the user runs `oauth-mux <harness>`, the
active subscription account exhausts, and another credited account is
substituted in place without restart, logout, manual resume, prompt, or
provider-owned session relaunch.

Everything below is in service of that bar. Route warming, restart,
prepared fallback, and synthetic smokes are evidence or diagnostics only.

## Current Live State

Observed on 2026-05-05 around 10:44 EDT:

- Repository: clean on `main...origin/main` at `83b23cf`.
- Selected live `codex-max` route: `max-4`.
- Selected route local token claim: `chatgpt_plan_type = "pro"`,
  subscription active until `2026-06-02T20:12:47Z`, last subscription
  check `2026-05-02T21:06:42Z`.
- All four configured Max routes locally claim `pro`; that proves tier
  metadata only, not available quota.
- Planner surfaces still mark `max-1`, `max-2`, and `max-3` as
  `quota_exhausted`.
- Their stored reset timestamps are in the past:
  - `max-3`: 2026-05-05 06:15 EDT
  - `max-1`: 2026-05-05 09:20 EDT
  - `max-2`: 2026-05-05 10:30 EDT
- `spare_fallback_ready:false` and `single_route_at_risk:true`.

Next live action after the operator's expected quota reset window:

```bash
./zig-out/bin/oauth-mux codex revalidate-exhausted --profile codex-max --capability codex-max --confirm-spend --json
```

If this revalidates at least one additional `codex-max` route as
available, run the Level 3 live acceptance path under TIN-951.

## Mainline Reality

Already merged on main:

- Broker MCP core.
- Codex adapter/proxy skeleton.
- Per-session `CODEX_HOME` overlay; account-local `config.toml` is not
  clobbered by adapter sessions.
- Synthetic Codex acceptance smoke: account A succeeds, then returns
  `usage_limit_reached`, then account B handles a post-swap turn in one
  stable child PID.
- Cassette capture/replay tooling; real operator capture data is still
  pending.
- `--json-status-file` artifact path, so oauth-mux status frames do not
  corrupt real Codex stderr/stdout.
- Unit and property tests for broker/session ids, credential handle
  parsing, header forwarding, quota classification, and per-session
  overlay behavior.

Not yet proven:

- Live provider-originated Level 3 account swap.
- Same-thread continuity across account swap.
- Mid-turn recovery.
- Bare `codex` plus a separate background oauth-mux daemon seamlessly
  handing off account state.

## Quarry Worktree

Worktree:

```text
/Users/jess/git/oauth-mux-broker  jess/broker-mcp-codex-adapter
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
   - Rewrite from current main rather than copying.
   - It should explicitly separate structural synthetic evidence,
     cassette replay readiness, and live Level 3 evidence.

6. `docs/policy/tos-posture-2026-05-03.md`
   - Policy posture is needed before public promotion.
   - Review for wording that could be read as quota evasion marketing.
   - Link from first-run/operator docs only after the mechanism is stated
     as operator-owned account enrollment and redacted evidence.

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
- Expired quota health: TIN-973 / GitHub #183 should make past reset
  windows show as `revalidation_needed` or equivalent, not indistinct
  active `quota_exhausted`.
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
   - Main currently proves synthetic between-turn A-to-B behavior.
   - Still need real evidence for whether same conversation thread survives
     account swap.
   - Do not claim mid-turn or same-thread recovery until captured.

4. Daemon-attached broker mode
   - In-process broker is good enough for current adapter smokes.
   - Multi-session, multi-harness route truth wants daemon-attached state
     later.

5. Bare `codex` path
   - The aspirational background daemon plus bare `codex` remains harder
     than `oauth-mux codex`.
   - Treat as future adapter/sidecar research, not the current acceptance
     gate.

6. Claude adapter
   - Important to prove broker contract generality.
   - Start only after Codex Level 3 acceptance or after the Codex blocker is
     explicitly parked.

## Local Todo Order

1. Keep main clean until after the 2:30 PM EDT quota window.
2. Revalidate exhausted `codex-max` routes with explicit spend
   confirmation.
3. If at least one fallback is selectable, run live Level 3 acceptance for
   TIN-951.
4. Fix TIN-973 / GitHub #183 so expired quota windows become
   revalidation-needed in planner output.
5. Rewrite the test/coverage review from current main and link it from the
   broker contract as an assessment, not a contract.
6. Review policy posture doc and add only if it does not market quota
   evasion.
7. Keep demoting route-warming/restart surfaces from product language.
8. Start the Claude adapter only after the Codex Level 3 proof is recorded
   or explicitly parked.
9. Re-run `just check-local` after each code/test slice.

## Hygiene Pass Notes

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
