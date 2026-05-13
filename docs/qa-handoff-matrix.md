# QA Handoff Matrix

Updated: 2026-05-10

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
| Managed resume chooser | `oauth-mux codex resume` | `resume_authority_check`, native chooser argv, `resume_authority_state_db_bridged` when `state_5.sqlite*` exists, no recursive pre-spawn rollout scan | covered by CLI smoke |
| Managed explicit resume | `oauth-mux codex resume <id>` | canonical session bridge, `resume_lookup_source`, redacted status, runtime identity | live-proven path |
| Managed last resume | `oauth-mux codex resume --last` | canonical session bridge, writeback check | covered by CLI smoke |
| Labeled reauth | `oauth-mux codex login-device <account>` | action says `user_handoff`, route label named, no raw identity | live operator flow |
| Auth fallback | selected route 401, fallback 200 | `proxy_auth_same_turn_retry`, `auth_health_observed quota_claim:false` | live and smoke evidence |
| Quota handoff | selected route `usage_limit_reached`, fallback 200 | `proxy_turn 429`, durable quota evidence, `proxy_same_turn_retry`, fallback `200` | live-proven for managed Codex |
| All fallbacks unavailable | every candidate rejected | `quota_handoff_failed_no_account_selectable` with redacted vector | synthetic; live/cassette target |
| Tier before fallback | B returns `usage_not_included`, C succeeds | B marked `tier_insufficient`, C selected | synthetic; live/cassette target |
| Reset-window repair | quota window expires | no-spend state becomes stale; confirmed revalidation repairs only with provider evidence | live target |
| API-credit false positive | subscription quota exhausted but API credits exist | Codex subscription route stays quota-blocked | live target |
| Child signal | Codex child killed/stopped | `session_aborted` with `term_kind`, `term_code`, `signal_name` | status regression added |

## Test Layers

| Layer | Spend/network | Purpose | Examples |
| --- | --- | --- | --- |
| Zig unit tests | none | parser/state invariants and status summarization | quota summary lifetime, child signal terminal fields |
| Shell smokes | none | CLI UX and local proxy behavior | chooser parity, config passthrough, 401, quota, tier, all-exhausted |
| Cassette replay | none after capture | real wire-shape regression without provider calls | scrubbed `usage_limit_reached`, 401, tier/rate captures |
| Live no-spend | no provider spend | installed binary route truth and runtime state | `route explain`, `doctor runtime`, `status-latest` |
| Live spend-confirmed | yes | provider-originated quota/auth/tier truth | `probe-all`, `revalidate-exhausted`, managed Codex dogfood |

## Current Codex Truth

- Managed Codex live quota handoff is proven for installed
  `oauth-mux codex resume`.
- The strongest preserved proof is
  `docs/evidence/codex-engineered-quota-handoff-20260509/`.
- Current no-spend route truth after that burn is `not_afloat` for
  `codex-max`: `max-1`, `max-2`, and `max-4` are quota-exhausted; `max-3` is
  runtime-ready but recorded `auth_permanently_failed`.

## Next QA Targets

1. Publishable cassette for real `usage_limit_reached` response shape.
2. Live or cassette-backed all-fallbacks-exhausted terminal vector.
3. Live or cassette-backed tier-insufficient before credited fallback.
4. Reset-window repair after quota reset with no manual health reset.
5. API-credit false-positive guard for subscription-backed Codex.
6. Same-thread continuity study, explicitly separate from managed handoff.
