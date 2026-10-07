# Omux whole-snapshot admission sprint

Status: active implementation plan for the experimental, unshipped native reset.
The user authorized the next goal and coordinated sprint after the saved evening
checkpoint. This plan elaborates the [reset](omux-native-account-lifecycle-reset-2026-10-02.md)
and the [whole-snapshot foundation](omux-native-evening-push-2026-10-03.md).
Requirements below are acceptance, not completed proof.

Start: `2026-10-04T05:29:41Z` / `01:29:41 EDT`.
Five-hour checkpoint: `2026-10-04T10:29:41Z` / `06:29:41 EDT`.
The [ledger](../../.goal/omux-native-admission-2026-10-04.json) preserves those
dates. The prior evening, morning and weekend dates remain unchanged.

## Outcome

Before an operation changes native configuration, contacts a provider, publishes
a usable lease or deletes custody, the actor must prove that its bounded result
and every durable outcome fit. Current request/mutation sections have independent
4/6 MiB reservations; these do not reserve the complete 16 MiB snapshot.

Use the actual locked JSON serializer through a bounded counting writer. Account
for the complete envelope, actual non-ledger metadata, worst-case request and
mutation reservations, and durable per-effect future-growth credits, including
the credit metadata itself. All persistence writers respect outstanding credits.
An unrelated operation cannot spend an accepted operation's completion space.

Each effect has an explicit bounded outcome plan including success, failure,
indeterminate and required retirement/tombstone growth. Persist its credit with
bounded per-list record-slot obligations as well as bytes: the domain's 1,024
record and 64-source-link limits can reject a completion independently of JSON
capacity. Codex import/usage may add up to 100 observations. Unrelated writers
must preserve these reserved slots too. Persist the reservation with
the original intent and generations before issuing the effect. Any debit for an
intermediate stage must be attributable to that operation and preserve the
remaining outcome bound. Release unused capacity only with a committed terminal
outcome or an explicit persisted cancellation fence proving that later completions
cannot mutate state. Restart, owner absence and endpoint replacement cannot
establish that fence, erase uncertainty or replenish attempt budgets.

Local atomic changes prepare and measure the complete candidate snapshot before
the SQLite transaction. External effects preflight both envelope space and the
encoded redacted result. Native configuration paths and thread lists must fit the
existing cached-result contract before configuration or detach changes occur.
Unknown provider output requires declared cardinality and encoded-size bounds;
missing bounds refuse admission. An unexpectedly oversized external outcome
retains indeterminate/quarantined custody and never repeats the effect.

Persisted credits require a versioned schema and explicit legacy handling.
Overcommitted or unresolved legacy obligations must refuse conversion before
effects rather than invent credits, drop authority, evict history or rekey work.
Preserve ciphertext-before-write, independently authenticated installation
checkpoints, wrapping-key custody, generation fences and two-attempt limits.
Admission cannot guarantee allocation, disk or transaction success; existing
poisoning and uncertainty behavior remains necessary.

The current storage boundary authenticates encrypted grants and independent
installation/checkpoint lineage. It does not MAC the complete metadata JSON.
Typed restoration validates private metadata, original work/method/generation
and plan/debit/remaining consistency. Import, request and observation bounds can
be recomputed from retained typed authority. Input-dependent external mutation
bounds cannot be reconstructed from their request fingerprint alone; unresolved
mutations have no restart completion, release or effect-resumption path. Future
reconciliation must retain a bounded typed original witness before enabling
those actions. Do not describe these predicates as full metadata authentication.

## Workstreams and file custody

Root owns this plan, ledger, evidence, session note, documentation classification,
root BUILD wiring, shared proof batches and final reconciliation. The existing
twelve authorized GPT-6.1 Sol workers are reused. Shared files have one writer.

| Workstream | Owner | Owned implementation or review |
| --- | --- | --- |
| Envelope and durable credit model | `evening_authority` | New snapshot admission module and request/mutation helper APIs |
| Actor integration and all effect paths | `evening_lifecycle` | Sole engine writer, persisted schema and fixture seams |
| Domain outcome bounds | `evening_install` | Sole domain writer; enrollment, leases, reports and forget growth |
| Native result preflight | `evening_codex` | Setup/native probe APIs and actual native overflow tests |
| Storage and crash recovery | `evening_vault` | Storage/recovery and real SQLite credit/uncertainty restart tests |
| Adapter saturation | `evening_clients` | Actual acquire/report termination and no-replay tests |
| Atomic account forget | `evening_journey` | Multi-source tombstone/ciphertext and rollback tests; journey review |
| Held import and fairness | `evening_reliability` | Actual held-import admission/fencing tests; measurement review |
| Independent safety review | `evening_security` | Every writer/effect census, outcome bounds and release audit |
| Declared graph and runbook | `evening_graph` | Source/test wiring review and current Apple toolchain guidance |
| External readiness | `evening_reapi` | Read-only source/carrier review; no repeated held-host probes |
| Tracker custody | `evening_linear` | Sole writer; prepared dated comments and exact parent readbacks |

## Required acceptance

| Gate | Actual path and required evidence |
| --- | --- |
| NA-MODEL | Actual serializer expansion and whole-envelope reservations are bounded; credit restoration rejects ambiguity and retains uncertainty. |
| NA-NATIVE | Oversized configuration path/thread-list result or insufficient envelope space refuses before native configuration, capability publication or detach effects. |
| NA-IMPORT | A held verified import protects encrypted completion space from unrelated mutations; lifecycle ABA, expiry, cancellation and forget cannot adopt a stale completion or release another credit. |
| NA-ADAPTER | Acquire reserves binding/lease/report growth before returning a handle; accepted work terminates under saturation without replay or a fresh attempt budget. |
| NA-FORGET | Multi-source tombstone expansion and ciphertext deletion commit atomically or refuse with all old custody/tombstones intact, including restart. |
| NA-RESTART | The external-effect/completion crash gap retains original intent and credits; duplicates do not repeat effects, and release requires durable terminal or cancellation evidence. |
| NA-RECONCILIATION | Necessary frozen-source tests/builds, source-derived facts, docs, scoped Linear readbacks and durable checkpoint match actual current inputs. |

Tests must exercise engine, storage and private native/import paths. Pure model
tests complement these gates. A reduced test ceiling alone is insufficient;
exercise actual valid persisted metadata at the production 16 MiB boundary.
Report fresh execution, matching-input cache and source review separately.

## Sequence and limits

First establish agreed bounded outcome APIs and the complete writer/effect
census. By the three-hour checkpoint, implement admission in the actual actor
paths and resolve independent-review blockers. By five hours, prove all five
actual-path gates, preserve receipts and reconcile product claims. Only after the
foundation passes review and proof may native owner custody or verified account
metadata extensions proceed. Their earlier appendices remain proposals until
their own implementation, migration and acceptance gates pass.

PZM remains GF-held under the supplied `gf-core-adoption-orchestration` context,
TIN-2998/GF#1717. Its dedicated APFS quota, mTLS/JWKS files, operation lock and
168-hour burn-in are GF prerequisites. Later lab R-C278–281 reports of Nix
upgrade, a trivial derivation, bounded jobs/cores, serialized GC and APFS
observations do not prove this worker or lift Omux's REAPI gate. Earlier SSH-ng
failures and capacity observations remain dated history, not current blanket
unavailability. Neo remains the teletype host.

Every executable/build/test/generator/package/check uses locked Nix+Bazel.
Root coordinates batches and declares invocation IDs. R-N13 governs mutation
receipts and durable notes; R-N11 forbids signaling other sessions. An actual
R-N12 guard-hook refusal stops that action and requires its stated escalation.
Lab switches, GC and service rulings do not authorize Omux host actions.

No provider spending, personal credentials, service activation, external
messages, publication or support promotion follows. Browser exports,
production renewal/revoke, installed Darwin and live ordinary-launch/resume
continuity remain separate gates. Reliability targets and repository roles
retain their existing contracts; no achieved SLO or contractual SLA is inferred.
