# QA Handoff Matrix

Updated: 2026-05-18

This matrix keeps handoff, reauth, resume, account-label, and cassette/live QA
claims in one place. It is subordinate to the broker and Codex adapter specs.

## Account Labels

Public docs and tracker comments should use route labels and capacity labels:

- `provider:account`, such as `codex:max-3`;
- capability key, such as `codex:max-3#codex-max`;
- role labels, such as `low-weekly primary`, `high-capacity fallback`,
  `weekly-exhausted reset-window candidate`, or `auth-dead repair candidate`.

Do not put raw emails, account ids, token claims, auth paths, or session ids in
repo docs or public tracker comments. Private identity mapping belongs in
operator-local files under `/tmp/`.

Subscription and account-shape labels should describe capability boundaries,
not people:

- subscription tiers: `codex-max`, `codex-plus`, `claude-pro`,
  `claude-max`, `figma-professional`, `figma-enterprise`;
- auth shapes: `oauth`, `pat`, `plan-token`, `console-api`, `app-token`;
- route roles: `primary`, `fallback`, `reset-window`, `auth-repair`,
  `tier-control`, `rate-limit-control`.

Do not infer subscription availability from unrelated API credits, dashboard
copy, or another model's quota. Each route earns a state only for the probed
capability, such as `codex:max-3#codex-max`.

## Route States

| State | Meaning | Safe next action |
| --- | --- | --- |
| `available` | Route has enough fresh evidence to select. | Use route or keep as fallback. |
| `quota_exhausted` | Provider reported subscription quota exhaustion. | Wait for reset or run confirmed revalidation after reset/plan change. |
| `rate_limited` | Provider throttled route but not subscription-exhausted. | Wait/retry according to policy. |
| `tier_insufficient` | Account cannot use requested capability. | Try another route; do not call it quota. |
| `auth_permanently_failed` | Upstream auth is invalid/stale. | Run labeled provider-owned login handoff. |
| `credential_unavailable` | Local materialization failed. | Repair local store/runtime; do not spend provider calls first. |
| `revalidation_needed` | Stored reset window expired; evidence is stale. | Run spend-confirmed revalidation. |
| `not_afloat` | No selectable route for the profile/capability. | Reauth, wait, revalidate, or enroll another route. |

## Handoff Patterns

| Pattern | Entry | Evidence required | Current status |
| --- | --- | --- | --- |
| Managed resume chooser | `oauth-mux codex resume` | `resume_authority_check` ok with diagnostic `isolated_persistent_store` on the default route-local home, native chooser argv, no recursive pre-spawn rollout scan; legacy `shared_canonical` opt-in instead requires `sqlite_authority:"canonical_env"` + `resume_authority_state_db_bridged` / `resume_authority_logs_db_bridged` | default mode unit-tested (TIN-2045 / #380); legacy bridge covered by CLI smoke |
| Managed explicit resume | `oauth-mux codex resume <id>` | route-local persistent home (default) or canonical session bridge (legacy opt-in), `resume_lookup_source`, redacted status, runtime identity | live-proven path (bridge era); default-mode re-proof rides the TIN-1852 e2e |
| Managed last resume | `oauth-mux codex resume --last` | route-local persistent home (default) or canonical session bridge (legacy opt-in), writeback check | covered by CLI smoke |
| Labeled reauth | `oauth-mux codex login-device <account>` | action says `user_handoff`, route label named, no raw identity | live operator flow |
| Auth fallback | selected route 401, fallback 200 | `proxy_auth_same_turn_retry`, `auth_health_observed quota_claim:false` | live and smoke evidence |
| Quota handoff | selected route `usage_limit_reached`, fallback 200 | `proxy_turn 429`, durable quota evidence, `proxy_same_turn_retry`, fallback `200` | captured evidence in `docs/evidence/codex-engineered-quota-handoff-20260509/` — route truth volatile |
| All fallbacks unavailable | every candidate rejected | `quota_handoff_failed_no_account_selectable` with redacted vector | synthetic and managed cassette harness covered; publishable provider cassette/live target |
| Tier selected-route classification | selected route returns `usage_not_included` | route marked `tier_insufficient`; no quota classification or same-turn quota retry | synthetic covered; live/cassette target |
| Tier before fallback election | already-tier-blocked B precedes credited C in route pool | B is not elected; C selected | unit matrix covered; live/cassette target |
| Reset-window repair | quota window expires | diagnostic state becomes stale; confirmed revalidation repairs only with provider evidence | live target |
| API-credit false positive | subscription quota exhausted but API credits exist | Codex subscription route stays quota-blocked | live target |
| Child signal | Codex child killed/stopped | `session_aborted` with `term_kind`, `term_code`, `signal_name` | status regression added |

## Test Layers

| Layer | Spend/network | Purpose | Examples |
| --- | --- | --- | --- |
| Zig unit tests | none | parser/state invariants and status summarization | quota summary lifetime, child signal terminal fields |
| Shell smokes | none | CLI UX and local proxy behavior | chooser parity, config passthrough, 401, quota, tier, all-exhausted |
| Cassette replay | none after capture | real wire-shape regression without provider calls | scrubbed `usage_limit_reached`, 401, tier/rate captures |
| Live diagnostic | no provider spend | installed binary route truth and runtime state | `route explain`, `doctor runtime`, `status-latest` |
| Live spend-confirmed | yes | provider-originated quota/auth/tier truth | `probe-all`, `revalidate-exhausted`, managed Codex dogfood |

## Coverage Reality

`just remote-check` already runs the synthetic smokes for the two highest-value
negative Codex UX lanes on the remote validation substrate:

- `scripts/smoke-codex-all-exhausted.sh` covers the all-fallbacks terminal
  vector, typed `503` repair body, redaction, and stable managed child PID.
- `scripts/smoke-codex-cassette-all-exhausted.sh` runs that terminal vector
  through the cassette replay server, proving the managed proxy/replayer
  boundary without provider traffic. It is still synthetic cassette content,
  not publishable provider-originated evidence.
- `scripts/smoke-codex-tier-insufficient.sh` covers
  `usage_not_included -> tier_insufficient`, no quota misclassification, and no
  same-turn quota retry.
- `scripts/e2e-local.sh` covers expired quota windows staying blocked as
  `revalidation_needed` until spend-confirmed provider revalidation.
- `scripts/smoke-codex-status-summary.sh` keeps the Python and native
  `status-latest` oracles aligned on quota-handoff success and terminal
  no-account-selectable failure shapes.

The remaining gap is not "no test exists"; it is provider-originated,
publishable evidence for those same negative shapes.

## Current Codex Truth

- Managed Codex live quota handoff is proven for installed
  `oauth-mux codex resume`.
- The strongest preserved proof is
  `docs/evidence/codex-engineered-quota-handoff-20260509/`.
- Current diagnostic route truth is volatile and must be refreshed before each
  live session. The 2026-05-17 22:24 EDT installed Homebrew `0.1.7` snapshot
  (historical snapshot, binary predates v0.1.14) is historical evidence, not
  current route truth; it was `not_afloat` for
  `codex-max` with all four named routes runtime-ready and broker-ready but
  route liveness `unrecorded`.
- The 2026-05-20 17:01 UTC diagnostic snapshot improved that to one selectable
  route (`max-3`) but still had no spare fallback; treat it as historical
  single-route-risk evidence.
- The 2026-05-21 02:57 UTC post-repair diagnostic snapshot used user-local
  `oauth-mux 0.1.9` (historical snapshot, binary predates v0.1.14):
  `codex:max-3#codex-max` is selected, `max-4` is a live
  selectable fallback, and `max-1` / `max-2` remain runtime/broker ready but
  blocked as `unrecorded`.
- Current resilience from that refresh is `session_start_ready:true`,
  `fallback_ready:true`, `single_route_at_risk:false`. Refresh immediately
  before any provider-spend run; do not treat this paragraph as future-proof.
- `oauth-mux codex status-latest --json` currently reports
  `brokered_without_fallback` from a rolling local artifact. This is stale
  relative to route truth and does not supersede the preserved quota handoff
  proof above; refresh this command before copying current-state claims into
  public release notes or tracker comments.
- `oauth-mux daemon status --json` currently reports no hosted stay-afloat
  loop. Its foreground tick snapshot is observational only and must not be cited
  as daemon-hosted continuity proof.

## Next Multi-Account Session

Start from the current installed `0.1.9` binary, or an explicitly installed
dogfood binary, and record provenance before any spend-confirmed test. As of
the 2026-05-20 release-hygiene refresh, public package lanes resolve to
`0.1.9`; use `oauth-mux version --json` to distinguish that package binary from
`~/.local/bin/oauth-mux` or `./zig-out/bin/oauth-mux` worktree dogfood hashes.

Diagnostic opening sequence:

```bash
oauth-mux version --json
oauth-mux codex preflight --profile codex-max --capability codex-max --json
oauth-mux route explain --profile codex-max --capability codex-max --json
oauth-mux repair-plan --profile codex-max --capability codex-max --json
oauth-mux stay-afloat next --profile codex-max --capability codex-max --json
oauth-mux codex status-latest --json
oauth-mux daemon status --json
```

Current matrix entry:

| Route | Current state | Session role |
| --- | --- | --- |
| `codex:max-1#codex-max` | blocked, `unrecorded`; runtime ready; `probe_needed` | route-health repair candidate |
| `codex:max-2#codex-max` | blocked, `unrecorded`; runtime ready; `probe_needed` | route-health repair candidate |
| `codex:max-3#codex-max` | selectable, live; selected | current primary |
| `codex:max-4#codex-max` | selectable, live | current spare fallback |

Do not start provider-spend cassette or negative-matrix work from memory. Rerun
the diagnostic opener first and verify `session_start_ready:true`,
`fallback_ready:true`, and `single_route_at_risk:false`; then proceed only with
explicit operator approval for the provider-spend capture. If the just-in-time
refresh falls back to single-route risk, pause and repair/probe before treating
the run as release-grade evidence.

Spend-confirmed activation sequence:

1. Refresh private quota UI for the four route labels and confirm the current
   `max-3` / `max-4` primary-fallback pair is still the least risky pair.
2. With explicit operator consent, run only the smallest targeted provider
   probe(s) needed to restore spare fallback if the diagnostic opener regresses;
   optionally probe `max-1` / `max-2` only when additional redundancy is worth
   the provider spend.
3. If a targeted probe reports auth failure, run only the labeled
   `oauth-mux codex login-device max-N` handoff for that route, then rerun the
   diagnostic opener and a spend-confirmed probe only if still needed.
4. Once `session_start_ready:true` and `fallback_ready:true` are reconfirmed,
   run the chosen negative/live permutation through the intended installed
   `oauth-mux` binary and record provenance.

Next spend-confirmed permutations should prefer negative coverage over another
happy-path quota proof: all-fallbacks-exhausted, tier-insufficient
classification plus later-election skip, reset-window repair, and API-credit
false-positive guards.

## Next QA Targets

These targets remain important production hardening work. They should not be
treated as public claims until captured. They do not block current package
parity, but they do block stronger Codex negative-matrix and release-proof
claims.

1. Publishable cassette for real `usage_limit_reached` response shape.
2. Publishable provider cassette or live all-fallbacks-exhausted terminal
   vector.
3. Live or cassette-backed tier-insufficient classification, then route
   election that skips the tier-blocked route before a credited fallback.
4. Reset-window repair after quota reset with no manual health reset.
5. API-credit false-positive guard for subscription-backed Codex.
6. Beta daemon status/handoff mediation proof that preserves the foreground
   tick semantics and does not claim unmanaged hot-swap.
7. Same-thread continuity study, explicitly separate from managed handoff.
