# TIN-2057 / TIN-1829 — 07-17 source-train and proof-surface sync

This is the dated successor to the immutable 2026-07-16 snapshot. It records
source and management truth only. **TIN-2057 remains exactly 0/11.**

## Source train

- #484 merged the compile-disabled `omux claude` refusal path as
  `d2c2673`, but it constructs the full inherited launch-environment map
  before refusing. No leak, provider lookup, child launch, or upstream call is
  shown.
- #485 merged as `d83b4083`, tree `218aea6c`: refusal now precedes full
  launch-environment, managed argv/config/binary, and launcher preparation.
  Normal process startup, logging initialization, and CLI argument parsing
  still precede the managed-launch gate.
- #483 composes one real generated session capability through the synthetic
  managed child environment and real loopback listener against the deterministic
  fake upstream. Its client is bounded to a 16 KiB response and a 5 s total
  deadline, with deterministic oversize and timeout negatives. Signed candidate
  `a8c24ae` passed GF `29559245015`, required CI `29559231358`, and Public
  Source `29559231401`, then merged as `d728435f`; its merge tree is exactly
  candidate tree `3ce61fb`.
- #486 merged the pure advisory-usage reader core as `809e30d8`, exact tree
  `54472c27`. It normalizes synthetic advisory rows, models freshness and a
  schema-drift kill switch, and gives reactive evidence precedence. It has no
  I/O or endpoint/resident wiring; its declared wire shape remains unverified
  against a real no-spend usage response and earns no Stage 2 or golden credit.
- Real forwarding remains compile-disabled. The #483 predicate generates and
  injects one synthetic memory-only session capability, but reads no provider
  OAuth/enrolled credential or real identity. No route, alternate, real Claude
  process, provider call, installed binary, or service mutation is involved.

## Evaluation truth

The current generic GF `test` and `check` lanes prove repository predicates,
not full v0.2 Stage 2 or G4. The ladder's exact-candidate and named-suite
requirements are not mechanically enforced by the current dispatch surface.
TIN-2989 now owns:

- immutable candidate-SHA checkout and provenance reconciliation;
- named Stage 1 local-debug, Stage 2 fake-upstream conformance, and G4 benchmark
  recipes;
- provider-egress denial, zero-call counters, predicate manifests, and explicit
  missing-predicate output.

Public Source remains complementary. TIN-2105 remains the parallel,
nonblocking Zig REAPI proof and cannot lend a remote-execution claim to this
program.

## Remaining Stage 2 gaps

The composed capability predicate does not close byte-preserving streaming and
cancellation, 401/403/429 attempt policy, 5xx pass-through,
ambiguous/started/oversize runtime no-replay, memory budgets, exact-model and
identity admission, abrupt-death reclamation, resident absence, bounded
all-exhausted behavior, shared leases, advisory-usage endpoint/wiring and live
schema qualification, or refresh-at-boundary semantics.

## Sequence

TIN-1788's TIN-2992/TIN-2991/TIN-2990 child train -> TIN-1790
provider-neutral core slices
-> TIN-2052 bounded lock wait/re-election -> TIN-1829 runtime mapping. TIN-2400
remains the separate exact-model/readiness lane. TIN-2989 owns making the
evaluation contract executable.

TIN-2050 owns the separate signed v0.2 prerelease profile. TIN-1759 blocks all
Stage 4 installed/service dogfood. The legacy Live Provider QA workflow is
v0.1 diagnostic infrastructure and cannot satisfy the v0.2 attended continuity
gate.

## Next-week lanes

1. Run TIN-1788 as the next three-slice core umbrella: TIN-2992 active-v2 and
   legacy/internal handle parsing, TIN-2991 exact Codex resume evidence, then
   TIN-2990 flock-owned refresh-outcome propagation. Promote Prompt 83 only
   after all three are accepted and TIN-1788 is Done.
2. Run TIN-2989 in parallel because it owns disjoint
   Just/workflow/proof files. Its first acceptance is an executable harness,
   not a Stage 2 or G4 pass.
3. Reconcile TIN-2050's v0.2 prerelease profile and TIN-1803's allowlist route
   snapshot contract without publishing or installing a candidate.
4. Treat #486 as TIN-2400's pure advisory-usage core only. Keep the separately
   owned exact-model single-route worktree held until its overlapping Claude
   proxy base is reconciled and its adversarial blockers are resolved.
5. Do not schedule Stage 4+ until Stages 0-3 are accepted and both
   `O-OWNERSHIP` and `R-TIN-1759` are accepted. `R-TIN-1759` requires TIN-1759
   Done with accepted proof linked; In Progress is insufficient. Any later live
   window needs explicit finite ownership, request/token/time/currency ceilings,
   and pre-commit human evidence review.

Schedule risk is real: TIN-1788 and its child train are due by July 25;
TIN-1790 August 1; TIN-1829 and TIN-2989 August 8; TIN-2040/TIN-2077 August 15;
TIN-2057 August 21.
TIN-1759 has no due date but blocks the entire installed/live half of the
ladder.

References: TIN-2057, TIN-1829, TIN-1788, TIN-2992, TIN-2991, TIN-2990,
TIN-1790, TIN-2052, TIN-2040, TIN-2077, TIN-1759, TIN-2050, TIN-2105,
TIN-2989; GitHub #463.
