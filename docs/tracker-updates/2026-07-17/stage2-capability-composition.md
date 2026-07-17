# Managed-capability composition checkpoint (2026-07-16 to 2026-07-17)

Status: exact source predicate merged; no Stage 2 exit or golden credit

## Exact candidate

| Field | Value |
| --- | --- |
| Pre-rebase source commit | `c655c7f0a777ac106d2004fc56ec19c0258da0c2` |
| Pre-rebase source tree | `72f953de56d111be0bcc5dd55ffa1e2aaebedd04` |
| Final candidate commit | `a8c24aed4dbfb4a8ef9a724337f83d75d966f38b` |
| Final candidate tree | `3ce61fb3572ac6ee88e6a088dc5f4331e4b03a3e` |
| Base commit | `d83b4083eff89584ecb2422acc999e9755c15429` (#485) |
| Stable patch ID | `1511f3edb0c286e41cc29abaecac6995f1b3082c` |
| GitHub update head | `5828bdd1dfc54ed3183acf68cfd45319b472cdfd` — preserves source commit and merges #484; still lacks #485 |
| GF Remote Test | `29559245015` — passed on final candidate; `29556300367` canceled on historical source |
| Public Source | `29559231401` — passed on final candidate; `29556671988` passed on obsolete update head only |
| PR CI | `29559231358` — passed on final candidate; all nine jobs successful |
| PR | #483 |
| Merge commit/tree equality | `d728435f62e1776d97837e5318c36a675752bf80`; merge tree exactly `3ce61fb3572ac6ee88e6a088dc5f4331e4b03a3e` |

PR #484 advanced `main` to `d2c2673` out of the intended train order. GitHub
then merged that `main` into #483 as `5828bdd`, but the update head preceded the
#485 repair and could not be accepted. #485 subsequently merged as `d83b4083`,
tree `218aea6c`; #483 was re-cut from `c655c7f` as signed candidate `a8c24ae`.
Its tree exactly matches the clean-composition tree precomputed before rebase.

Independent review rejected #483's earlier candidate because the synthetic
loopback client could read an unbounded response and wait indefinitely for
EOF. The amended candidate adds a 16 KiB response cap, a 5 s total response
deadline, plus deterministic oversized-response and stalling-peer timeout
tests. Every run on `28e92cd`, `c829e86`, `fd2c099`, or `5828bdd` is historical
only. The table above distinguishes that history from the active exact
candidate.

## Predicate

The two-file, test-only slice composes one real generated
`SessionCapability` through `runPrepared`, the managed child environment,
and the real loopback listener backed only by the deterministic
`FakeUpstream`.

The named test requires:

- one synthetic child spawn;
- local 401 for missing and wrong carriers;
- fake 204 for the valid carrier;
- exactly one fake-upstream attempt and call;
- exactly two allowlist-redacted rejection events;
- a bounded synthetic response read with deterministic oversize and timeout
  rejection;
- capability revocation before listener teardown;
- cleared carrier and child environment;
- filesystem activity confined to the testing temporary directory.

## Claim boundary

The exact-head source proof makes only this statement available:

> The managed-capability-composition predicate passed remotely with zero
> provider calls.

This is one partial Stage 2 predicate, not Stage 2 exit. It generates and
injects one synthetic, memory-only session capability, but does not expose a
working `omux claude`, launch real Claude Code, read or inject a provider
OAuth/enrolled credential, use a real identity, contact Anthropic, select a
route, replay a request, switch accounts, qualify Stage 3, satisfy G5,
authorize installed/service dogfood, or move TIN-2057 from `0/11`.

## Next source train

1. Finish TIN-1788's three child slices: TIN-2992 active-v2 and
   legacy/internal handle parsing, TIN-2991 exact Codex resume evidence, and
   TIN-2990 flock-owned refresh-outcome propagation. This umbrella is the
   accepted prerequisite for the shared broker core and must not be
   reimplemented inside the Claude adapter.
2. Under TIN-1790, land a provider-neutral pure request-attempt reducer that
   mechanically enforces one second attempt: either confirmed-not-sent
   same-route retry or one replayable pre-body 401/403/429 alternate, never
   both. Provider 5xx, ambiguity, downstream-started responses, cancellation,
   and replay-budget overflow do not cross accounts.
3. Keep exact-model admission, identity/election wiring, streaming and memory
   reservations, shared leases, and advisory usage as separate later slices.

No provider OAuth/enrolled credential access, provider call, real identity,
install, service mutation, or live continuity action is authorized by this
record.
