# Redacted route-state truth for v0.2 accounts/status/doctor (TIN-1803)

Status: **declaration + golden fixtures only, unshipped**. This is the
tractable slice of TIN-1803 per the tranche-3 verdict (issue still Todo,
zero PRs/attachments, only a 2026-07-11 scope-narrowing comment). It does
not add a reducer, wire `status`/`statusline`/`doctor` to a shared output,
or touch `src/`. It follows the same declaration-first idiom this repo
already uses for `docs/spec/managed-harness-jsonrpc-v2.md` /
`schemas/managed-harness-jsonrpc-v2.schema.json`: schema first, golden
fixtures (valid + invalid-schema + invalid-semantic) second, a Zig
projector and live reducer wiring later as separate, reviewed work.

## Why this is a converge, not a new model

TIN-1803's Scope explicitly says: "Reuse existing route-explain output; add
only missing fields and converge duplicate vocabularies." Checking that
claim against `src/types.zig` / `src/health.zig` today: **eight of the
nine required states already exist as typed Zig values**, just scattered
across three separate unions instead of one redacted envelope:

| TIN-1803 required state | Existing Zig authority |
|---|---|
| known-good | `CredentialLiveness.live` + `Availability.available` |
| rate limited | `Availability.rate_limited` (`RateLimitInfo`) |
| quota exhausted with reset | `Availability.quota_exhausted` (`QuotaInfo.window_resets_at`) |
| tier insufficient | `CredentialLiveness.degraded` + `DegradedReason.tier_insufficient` |
| auth permanently failed | `CredentialLiveness.dead` + `DeadReason.auth_permanently_failed` |
| credential unavailable | `CredentialLiveness.dead` + `DeadReason.credential_unavailable` |
| revalidation needed | `RuntimeReadiness.needs_reauth` (`ReauthInfo`) |
| quarantined | `runtime.zig`'s `disposition.quarantined` / `hard_lineage_invalidated` lineage state |
| unknown / reactively eligible | **not represented today** — no health record exists yet for a route nobody has probed. This is the one genuinely new state. |

This confirms the ticket's own framing: the missing piece is not new
provider-health modeling, it is (a) a redaction/projection layer over what
already exists, and (b) the one new `unknown` state for never-probed
routes, and (c) an explicit total order across all nine so `status`,
`statusline`, and `doctor` stop each inventing their own presentation
logic.

## Redacted envelope

Declared in `schemas/route-state-v2.schema.json`. One record per route:

```json
{
  "route_handle": "opaque, matches the managed-harness-v2 handle idiom",
  "state": "one of the 9 enum values",
  "provenance": "existing ProbeEvidenceSource value, or never_probed",
  "freshness_deadline_ms": "epoch ms; re-probe after this, don't trust stale",
  "trusted_reset_at_ms": "optional; only for rate_limited/quota_exhausted",
  "active_lease_count": "integer >= 0",
  "action_class": "coarse next-step only -- none | wait_for_reset | reauth_user_mediated | operator_repair | do_not_select"
}
```

Deliberately **absent**: raw account id, email, token, refresh token,
request/response body, or any field not in the schema
(`additionalProperties: false`). `route_handle` reuses the
already-redacted handle idiom from `test/fixtures/managed-harness-v2/`
rather than inventing a second opaque-id convention.

## Total order (the one open design call)

The ticket only pins two points: *"Unknown ranks below known-good and
above dead/quarantined."* Everything else is this document's proposal, not
a ratified decision — a future implementer or reviewer should confirm or
revise it before wiring a reducer to it:

```
known_good
> unknown
> rate_limited
> quota_exhausted
> tier_insufficient
> revalidation_needed
> credential_unavailable
> auth_permanently_failed
> quarantined
```

Rationale for `unknown` sitting directly under `known_good`: an
unprobed-but-selectable route is structurally no worse than a route that
is *known* to be temporarily degraded — it just hasn't been tried. Ranking
it below every degraded state would make "we haven't checked yet" look
worse than "we checked and it's currently rate-limited," which inverts the
ticket's own ordering intent. `credential_unavailable` outranks
`auth_permanently_failed` on the theory that the former can sometimes
recover without operator action (a missing secret can be supplied) while
the latter cannot; both outrank `quarantined`, which is a hard stop by
design (`runtime.zig`: `hard_lineage_invalidated`).

`test/fixtures/route-state-v2/valid/00-rank-order.json` encodes this order
as data so a future reducer's tests can assert against it directly instead
of re-deriving it from prose.

## Golden fixtures

`test/fixtures/route-state-v2/valid/` — one fixture per state (9 files) plus
the rank-order fixture above, all schema-valid and redaction-clean.

`test/fixtures/route-state-v2/invalid-schema/` — fixtures a JSON Schema
validator alone must reject: an extra raw-looking field, a wrong-typed
`active_lease_count`, an out-of-enum `state`.

`test/fixtures/route-state-v2/invalid-semantic/` — fixtures that are
schema-valid but violate a rule JSON Schema cannot express by itself
(mirroring the `validate-managed-harness-instance.py` pattern for the
managed-harness surface):

- `state=unknown` with a non-`never_probed` provenance (unknown must mean
  "never actually probed," not "probed and inconclusive").
- `state=known_good` with `trusted_reset_at_ms` present (that field only
  makes sense for the two window-bound states).
- A `route_handle` value that looks like a raw email/account id
  (`user@example.com`), to prove the redaction lint actually fires.

`scripts/validate-route-state-instance.py` checks exactly those three
rules, following `scripts/validate-managed-harness-instance.py`'s
structure (typed `ContractError`, one `validate()` entrypoint, a `main()`
that takes a fixture path and exits non-zero on any violation).

## Verified locally (no Zig build; no compiler used)

```
$ python3 -m jsonschema -i <fixture> schemas/route-state-v2.schema.json   # every valid/ fixture: passes
$ python3 -m jsonschema -i <fixture> schemas/route-state-v2.schema.json   # every invalid-schema/ fixture: fails
$ python3 scripts/validate-route-state-instance.py <fixture>              # every valid/ fixture: exit 0
$ python3 scripts/validate-route-state-instance.py <fixture>              # every invalid-semantic/ fixture: exit 1
```

See the commit's proof log for the actual run output against every
fixture in this PR.

## What remains (not done here, needs a Zig-capable pass)

1. A `route_state.zig` (or extension of `health.zig`) that actually
   projects `CredentialLiveness` + `Availability` + `RuntimeReadiness` +
   the quarantine/lineage state into this schema's `state` enum, per the
   mapping table above.
2. A schema-projector (`just route-state-schema-update`, mirroring
   `just managed-harness-schema-update`) so the Zig source stays the
   single authority and this hand-written schema stops being
   hand-maintained.
3. Wiring `status`, `statusline`, and `doctor` (`src/cli.zig`) to call the
   same reducer and emit the same redacted shape — the acceptance item
   "status/statusline/doctor agree on the same reducer output" needs all
   three call sites converged, not just one.
4. A "remote check" (per Acceptance) once the reducer exists to run against
   live route state, not just static fixtures.

## Sources

- Linear TIN-1803, tranche-3 verdict (`classification: still-real`, Todo,
  zero attachments).
- `src/types.zig` (`CredentialLiveness`, `Availability`, `DegradedReason`,
  `DeadReason`, `RuntimeReadiness`), `src/health.zig`
  (`ProbeEvidenceSource`), `src/runtime.zig` (`quarantined`,
  `hard_lineage_invalidated`).
- `docs/spec/managed-harness-jsonrpc-v2.md`,
  `schemas/managed-harness-jsonrpc-v2.schema.json`,
  `scripts/validate-managed-harness-instance.py`,
  `test/fixtures/managed-harness-v2/` — the declaration-first idiom this
  document follows.
