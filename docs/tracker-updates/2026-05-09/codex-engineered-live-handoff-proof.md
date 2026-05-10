# Codex Engineered Managed Live Handoff Proof

Redacted tracker-safe update:

- Installed `oauth-mux codex resume <session-id>` produced a managed Codex live
  quota handoff artifact during the engineered low-weekly window.
- The source status artifact is
  `<oauth-mux-state>/codex/status/managed-1778362718969.ndjson`; the reviewed
  redacted bundle is
  `docs/evidence/codex-engineered-quota-handoff-20260509/`.
- Evidence shape:
  - primary route `codex:max-2` returned successful `200` `responses` traffic;
  - the same route later returned provider-originated
    `429 usage_limit_reached` / `classification:"quota_exhausted"`;
  - oauth-mux recorded quota, did not deliver the 429 to Codex, dropped
    `x-codex-turn-state`, and retried the same buffered request on
    `codex:max-3`;
  - fallback route `codex:max-3` returned `status:200`;
  - status oracle verdict:
    `verdict:"successful_live_quota_handoff"`,
    `provider_originated_live_fallback_claim:true`,
    `user_visible_failure_likely:false`.
- Active follow-up observation: a still-growing installed-runtime artifact
  (`<oauth-mux-state>/codex/status/managed-1778276571386.ndjson`) also
  summarizes as `successful_live_quota_handoff`, with traffic on both
  `codex:max-2` and `codex:max-3`, two provider `usage_limit_reached` events,
  and fallback `200` responses.
- Current post-run route truth is intentionally not afloat:
  `codex:max-1`, `codex:max-2`, and `codex:max-4` are quota-exhausted;
  `codex:max-3` is runtime-ready but recorded `auth_permanently_failed`; route
  explain reports `not_afloat` and no selectable fallbacks.

Claim boundary:

- Proven: managed Codex live quota handoff for installed
  `oauth-mux codex resume`.
- Still separate: same-thread continuity semantics across account boundaries,
  mid-turn streaming recovery, unmanaged bare-`codex` daemon handoff,
  non-Codex harness behavior, all-fallbacks-exhausted UX, tier-insufficient
  sequencing, reset repair, and API-credit false-positive permutations.
