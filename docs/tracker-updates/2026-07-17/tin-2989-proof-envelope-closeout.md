# TIN-2989 - immutable v0.2 proof-envelope closeout

Status: executable proof infrastructure accepted; Stage 2 and G4 remain
intentionally incomplete; TIN-2057 remains exactly 0/11

This record is the exact-candidate successor required by TIN-2989. It records
proof-harness behavior only. It does not promote v0.2, accept a Stage 2 exit,
accept the G4 row, or authorize installed or provider-backed dogfood.

## Exact candidate

| Field | Value |
| --- | --- |
| Signed PR candidate | `afebd56e7cbfa29354dd20c3addd6207e12035fd` |
| Candidate tree | `3d889bb902c5739bcc8b7bc954224dee94a7d7bb` |
| Base | `2647d75f01cf5da71a624e73acba1141028940ae` |
| PR | #489 |
| Merge commit | `ae2a9403d9376fa946bb5defaf2dc5f7efd1df4f` |
| Merge tree | `3d889bb902c5739bcc8b7bc954224dee94a7d7bb` |

The one-commit candidate carried a valid Jess Sullivan GPG signature. The
squash merge preserves its exact tree.

## Accepted source proof

| Lane | Run | Result |
| --- | --- | --- |
| GF remote test | `29575188225` | passed on the signed candidate |
| GF remote check | `29575652551` | passed on the signed candidate |
| PR CI | `29575178989` | all ten jobs passed, including six cross-compiles |
| PR Public Source | `29575178968` | passed without private GF inputs |
| Post-merge Public Source | `29576382105` | passed on the merge commit |
| Post-merge CI | `29576382054` | all nine jobs passed on the merge commit |

These runs prove source and public-source predicates. They are not Stage 2,
G4, installed-candidate, or live-provider evidence.

## Fail-closed control dispatches

Both controls used a temporary frozen branch resolving to the exact merge
commit. The branch was deleted after the wrapper reconciled the run event SHA,
detached checkout, candidate tree, artifacts, and result.

| Target | Run | Expected result | Verified artifacts |
| --- | --- | --- | --- |
| `v02-stage2-conformance` | `29576421753` | failed: all 124 ordered predicates are `missing` | `v02-proof-provenance.json`; `v02-proof-predicate-manifest.json` |
| `v02-benchmark` | `29576719144` | failed: G4 predicates and measurements are `missing` | provenance; predicate manifest; `v02-benchmark-metrics.json` |

The local dispatch wrapper returned nonzero only after verifying each
allowlisted artifact against merge commit
`ae2a9403d9376fa946bb5defaf2dc5f7efd1df4f`, tree
`3d889bb902c5739bcc8b7bc954224dee94a7d7bb`, the workflow run ID and attempt,
the `tinyland-nix` worker class, the pinned GloriousFlywheel action source, and
the failed result. The pinned GF action source was
`2357988536f1f6258291c363e1428962b6cced1b`; provenance recorded
`local_fallback_occurred=false`. No raw SHA dispatch, mutable-ref drift, local
fallback, or unverified artifact can satisfy the proof contract.

## What TIN-2989 closes

- Generic development `test` and `check` dispatch remains available, but it
  cannot be represented as Stage 2 or G4.
- v0.2 proof dispatch requires an exact 40-hex candidate and an unambiguous
  branch or tag resolving to it. Workflow event SHA and detached `HEAD` must
  match.
- Stage 2 has one canonical, ordered 124-predicate schema. Missing, reordered,
  duplicated, unknown, malformed, or falsely all-pass manifests fail closed.
- G4 has a separate strict metrics schema for latency, throughput, RSS, replay
  memory, stale reservations, and 20-session/50-account fairness.
- Candidate and checked-out source, including ignored outputs, must remain
  clean. Only the exact allowlisted JSON proof artifacts may be emitted.
- Local Stage 1 output remains labeled `local_debug_only`.

## Remaining promotion work

Stage 2 now needs implementations that turn every required fake-upstream
predicate from `missing` to accepted proof while provider egress remains
structurally denied. TIN-2040 owns the measured G4 workload and budgets. Stage
3 still owns carrier, surface-v2, redaction, and death qualification.

Stage 4 remains closed until TIN-1759 is Done with accepted proof and a fresh
`O-OWNERSHIP` gate is accepted. Stages 5-7, provider spend, installed service
mutation, golden rows, prerelease promotion, and the beta cohort remain
unauthorized by this checkpoint.

References: TIN-2989, TIN-2057, TIN-2040, TIN-1829, TIN-1759; GitHub #463 and
PR #489.
