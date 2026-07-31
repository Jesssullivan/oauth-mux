# TIN-2057 - v0.2 execution recovery checkpoint

Status: program off track; implementation resumed; golden score remains 0/11

This checkpoint reconciles the repository after the July 19-31 execution gap.
It records current source and proof truth only. It does not authorize provider
calls, credential reads, installed-candidate changes, service mutation, or
provider-backed dogfood.

## Product bar

The unchanged acceptance is one managed harness process and context, the exact
requested model, at most one distinct-account alternate, and no login or
restart. Manual browser/account switching and canonical-keychain mutation are
research inputs, not managed continuity proof.

## Accepted truth

| Surface | Current truth |
| --- | --- |
| Stable release | v0.1.15; shipped behavior is bounded by its changelog and evidence, with no v0.2 managed-broker continuity claim |
| Current source | `831d10b` / PR #513; pure exact-model route core plus serialized in-process lease state |
| Stage 2 | latest accepted packet is 73 pass / 0 fail / 51 missing on ancestor `976fc15`; current source has no accepted recut |
| G4 | 0/6 measurements accepted |
| Installed v0.2 | unauthorized while TIN-1759 remains open |
| Claude production forwarding | compile-disabled |
| Golden metric | TIN-2057 remains exactly 0/11 |

PRs #512 and #513 merged after exact-head GF Test, GF Check, PR CI, Public
Source, and independent adversarial review passed. Each merge tree equals its
reviewed candidate tree. Together they prove only the pure Group 1 reducer and
serialized in-process Group 2 lease machinery. A post-merge adversarial
reproduction found that unrelated continuous renewals can repeatedly invalidate
revision-fenced admissions; #513 therefore earns no admission-liveness or
no-starvation claim. Neither slice advances Stage 2 or golden acceptance.

## Recovered execution train

1. Group 2 landed in PR #513 with value-free in-process lease state and seeded
   schedule coverage. Correct the renewal-induced admission livelock before any
   liveness, no-starvation, or G4 claim. Cross-process lease ownership, stale-PID
   cleanup, G4 fairness, and adapter behavior remain outside #513. TIN-3320 owns
   the cross-process representation and stale-owner recovery explicitly.
2. Group 3: map the Claude fake-upstream path to the shared demand, observation,
   decision, and lease reducers. Only wire-exercised predicates may move; the
   unmerged managed-boundary guard must be folded, count-adjusted, and kept fail
   closed before this slice lands.
3. Add the bounded Codex adapter mapping required by TIN-1790. The ticket remains
   open after a Claude-only mapping even if its seven wire predicates pass.
4. Recut Stage 2 on the resulting immutable candidate. No ancestor packet may
   be inherited across product changes.
5. Complete all remaining Stage 2 groups, then implement and measure all six G4
   metrics on the same candidate before Stage 3 qualification.
6. In parallel, close TIN-1759 containment and turn planning-only setup/repair
   plus declaration-only packaging into a real installable flow. Installed or
   provider-backed dogfood starts only after the evaluation ladder permits it.

## Product-readiness gaps

- `omux setup` and `omux repair` currently plan but do not execute enrollment,
  provider-owned login, consent, service enablement, or readiness proof.
- `omux claude` refuses before credential access, child launch, or production
  forwarding.
- v0.2 archives, signatures, SBOM/provenance, package consumers, install,
  upgrade, and rollback remain unproven.
- Codex has historical v0.1 handoff evidence but not the v0.2 one-alternate,
  same-context proof. OpenCode remains a declaration-level conformance target.
- The installed command aliases are version-skewed across local package paths;
  TIN-2723 and TIN-2799 own version/PATH/install truth.

## Near-term success criterion

The next honest product milestone is not a release claim. It is one immutable
candidate with complete fake-upstream Stage 2, measured G4, and Stage 3
qualification, while TIN-1759 and setup/package execution advance in parallel.
Stage 4 may begin only after O-OWNERSHIP and R-TIN-1759 are accepted, then must
pass installed-candidate and rollback rehearsal. Attended Stage 5 shadow/manual
route dogfood additionally requires S-PROVIDER-SPEND and a named TIN-2077
window. The first golden Claude result remains Stage 6: account A exhausts,
account B is selected, and the same Claude process completes with exact model
and context without login or restart.

References: TIN-1790, TIN-1759, TIN-1829, TIN-2040, TIN-2057, TIN-2400,
TIN-2723, TIN-2799, TIN-3320; GitHub #463; PRs #512 and #513; Prompt 85 and
prompts-enqueue #169.
