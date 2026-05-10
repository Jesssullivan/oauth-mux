Update after the 2026-05-08 installed-runtime dogfood:

We now have managed Codex quota-handoff evidence from an installed
`oauth-mux codex resume <id>` run. The preserved, reviewed proof bundle is in:

- `docs/evidence/codex-managed-quota-handoff-20260508/status-excerpt.ndjson`
- `docs/evidence/codex-managed-quota-handoff-20260508/status-summary.json`
- `docs/spec/codex-live-quota-handoff-evidence-2026-05-08.md`

Observed shape:

- `codex:default` returned provider-originated `429 usage_limit_reached` on
  `POST /backend-api/codex/responses`
- oauth-mux recorded quota evidence and did not deliver the 429 to Codex
- oauth-mux dropped `x-codex-turn-state`
- oauth-mux retried the same buffered request on `codex:max-2`
- `codex:max-2` returned `status:200`
- the status oracle reports `verdict:"successful_live_quota_handoff"` and
  `provider_originated_live_fallback_claim:true`

Supersession, 2026-05-09: the deliberately engineered managed-session
exhaustion case has now been captured in
`docs/evidence/codex-engineered-quota-handoff-20260509/`: successful primary
traffic, provider-originated `usage_limit_reached`, retry to a distinct
fallback route, and fallback `status:200`.

Recommended tracker state: this issue can count the managed quota-handoff bug
as fixed/proven. Keep follow-ups open for same-thread semantics, unmanaged
daemon handoff, API-credit vs subscription-quota false positives, all-fallbacks
exhausted, tier-insufficient sequencing, and reset repair.
