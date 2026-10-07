---
title: Omux native owner authority review
date: 2026-10-04
status: review-only
summary: R-N13 review of the selected bounded native custody and checkpoint commitment, with platform witness proof still required.
refs:
  - R-N13
  - R-N11
  - R-N12
  - TIN-5337
  - TIN-5338
---

This note is an R-N13 review write, not implementation authorization or a passing
receipt. It follows the [active reset](../plans/omux-native-account-lifecycle-reset-2026-10-02.md)
and [proposed owner stage](../plans/omux-native-owner-custody-next-stage-2026-10-04.md).
The initial interview was pending during this review. The subsequent R-N13 user
selection authorizes native owner plus Codex protocol work with Linux installed
proof, under the `08:28:06Z`–`13:28:06Z` sprint. Root adopts the bounded reference
and ceilings below and one exact metadata-byte/revision checkpoint commitment.
Actor startup must refuse **all unsealed v1 authority unchanged before recovery
or effects**; usable legacy migration remains held. That decision supersedes this
note's conditional migration options below. No build, test, process probe,
provider call, service action or tracker write was performed for this review.

The final checkpoint `c73368fb-f1f9-4e49-9be7-ff39de3ce290` records source
`2af1f8868ac63a759e31ea145d8e210c4f7a2551cdedfe7104dc46ada530c73c`
(3,984,317 bytes, 271 members), runtime
`8f54e896fd38d97d7833f33e4f2fbcdbe44480049634f7bce724ab1fb77befdc`
(59,990,114 bytes), and local suite `083589b8` with 66 passed targets,
15 fresh and 51 matching-input cached. Its installed Sting receipt applies to
the exact runtime and its recorded earlier source epoch; the final source differs
only in documented context. It proves its declared local predicates, not native
owner attribution or seamless live continuity. This proposal inherits none of
those missing capabilities.

## Smallest bounded authority model

Use one actor-owned native ledger in the same private persisted snapshot. An
owner row records an opaque 32-byte owner ID, application, adapter epoch, original
verified process/endpoint witness and native process nonce. An attachment row
records the exact native thread ID, thread-instance and attachment generations,
original registration operation, current phase and any stable removal operation.
Include registrations that never acquired a credential. Retain the same row as
its retirement tombstone; do not append an unlimited parallel tombstone list.

The proposed shared `NativeRef` is `{ owner_id: [32]u8, adapter_epoch: u64,
endpoint_generation: u64, thread_instance_generation: u64,
attachment_generation: u64 }`. Binding and lease carry this optional reference;
all four generations must be nonzero. Null means legacy/unattributed, never an
inferred current owner. Route generation
remains independent. References compare exact values, while the engine verifies
their linkage to trusted ledger and runtime peer evidence. For the first bounded
model, allocate a new owner incarnation row for a changed endpoint generation
or adapter epoch; never overwrite its original witness. The process-stable owner
ID may recur only when all its earlier rows are exactly retired. The immutable
row key is `(owner_id, adapter_epoch, endpoint_generation)`; that full key is
never reused. An ID-only lookup refuses ambiguity rather than selecting the
latest row. This avoids a second unbounded endpoint-history list and
conservatively treats replacement as new custody.
It does not grant that replacement the original owner's work or report rights.

The selected experimental ceilings are 256 lifetime owner incarnation records
and 4,096 combined lifetime attachment generations and application-removal fences,
including unresolved and retired rows. The R-N13 implementation draft now records
these limits; full actor integration and installed proof remain pending. Focused
results belong to the root-owned evidence record. They do not promise that all
records fit simultaneously. Preserve the native probe's 256-byte thread-ID bound.
Owner discovery allows at most 1,024 entries and must fit the actual 64 KiB
packet; an unprepared entry or capacity failure refuses the whole list. Legacy
read-only WebSocket discovery retains its separate bounds and cannot confer
owner authority. Expose actual remaining byte and slot headroom as well as ceilings. Refuse at
capacity; no TTL, periodic eviction or daemon epoch discards authority. Normal
owner churn can exhaust these lifetime limits, so usability and any future
authenticated retirement/epoch compaction contract remain explicit decisions.

Registration starts `pending_registration`; exact acknowledgment can produce
`attached`. Detach first persists `pending_detach`. Missing or mismatched replies
remain unresolved. `retired` requires an acknowledgment matching the original
owner, process nonce, endpoint, adapter epoch, thread generation, attachment
generation and operation, together with applicable request/lease fences. A
retired generation never becomes attached again; explicit reattachment creates
another bounded generation. A live handle or restored phase cannot authorize
automatic retransmission of registration, detach or model work.

The R-N13 ledger draft also retains a sealed private endpoint path and an
application-wide removal row. That row fences new same-epoch owners even when
no owners exist. A replacement attachment cannot be admitted until all earlier
rows for that owner's native thread retire; thread-instance generations are
unique across that owner incarnation's threads. An exact verified registration
acknowledgment of no effect can retire its original pending row without inventing a detach
operation. The native ledger's actual serialized attribution and conservative
future phase/retirement/operation encoding widths are separately prepaid from
effect outcome credits. These source predicates require their current-input
focused tests and actor integration gates; they are not native liveness or
continuity evidence. Generation selection scans only the exact qualified owner
incarnation and thread instance, starting at 1 when the new incarnation has no
retained matching rows. The producer's `owner/threads` attachment generation is
only a latest-known diagnostic hint, never admission or reconciliation authority.

Explicit preinstall late attach requires an owner endpoint path and fresh peer
proof; no automatic filesystem advertisement enrolls a process. Native
construction without Omux configuration retains its ordinary behavior. Producer
reconnection after real daemon restart and reconciliation of uncertain native
effects remain unimplemented and held; synthetic retained actor reports cannot
prove either capability.

## Original work and peer custody

Keep the request key exactly `(application, native session, original request_id)`.
Put `NativeRef` in immutable request intent constraints; do not add it to the
work-key namespace. A different owner is a mismatch even after a safe first
rejection. Owner replacement, daemon restart and attachment reconciliation never
reset the two-attempt budget or mint a replacement UUID for accepted/unknown work.
Owner-qualified binding identity isolates two processes loading the same thread.
Materialization, metadata, release and reports check the exact reference.

The runtime peer witness must be constructible only from verified socket-derived
context passed internally to the actor. Client JSON cannot choose its PID, UID,
incarnation, endpoint identity or a `verified` flag. Store a bounded original
platform-profile witness plus native nonce; an FD number is never durable proof.
The Linux profile needs the retained connected-peer handle and a reviewed
incarnation/boot/namespace representation. Numeric PID lookup, private path,
socket inode and native nonce individually are insufficient. Reconnect, PID reuse
and socket delegation semantics are platform blockers until actual tests prove
the chosen profile. The OS reviewer proposes `linux_pidfs64_v1`: fixed 16-byte
boot ID, pidfs device/inode, verified user and PID namespace identities, and
verified UID/GID. Runtime socket-origin `SO_PEERPIDFD` and per-read `SCM_PIDFD`
must both identify the same reviewed pidfs process; numeric PID is observational.
This candidate requires actual kernel, namespace and per-segment delegation
proof. Current libcurl WebSocket framing does not establish those receive
predicates, and no numeric `/proc` fallback may fill the gap. Darwin remains
unsupported for this owner capability until its independent incarnation profile
is reviewed and tested. This paragraph records an R-N13 proposed OS contract,
not an executed OS probe or supported profile.

On restart, sealed original witnesses preserve attribution but owners start
unverified/unresolved. A surviving process needs fresh bidirectional peer proof
matching the original witness and reference before receiving scoped authority.
Absence or replacement does not retire it. A persisted removal fence excludes
new registration, acquire and materialization while allowing existing accepted
or unknown work to submit its original scoped terminal report. That exception
permits no new credential or native effect. Shared capability retirement and
configuration restoration wait for every required owner acknowledgment and
remaining request fence; setup `recover` and `install` cannot bypass this rule.

## Checkpoint commitment instead of fabricated witness recovery

At the reviewed admission checkpoint, `FileAuthority` authenticated installation,
sequence and nonce, without authenticating snapshot bytes or revision. Typed
self-consistency cannot prove that mutable owner JSON came from an originally
verified peer. Adding another
per-owner MAC over the same mutable values would not supply that provenance.

With the storage reviewer, prefer one explicit v2 extension of the independently
authenticated checkpoint: bind the snapshot revision and SHA-256 of the exact
stored metadata bytes into its existing authenticated payload and domain/version.
The matching SQLite checkpoint, metadata and original witness admission commit
together. An owner-only digest is inadequate: mutable request attempts, binding
and lease constraints, growth credits, outcome intents, epochs and retirement
fences could change while the owner digest stays valid. Committing the existing
whole bounded snapshot avoids a fragile dependency projection and extra copies.
This is the selected new storage boundary; its source and executed predicates
are recorded separately from this review and do not establish live reconciliation.

Before effects, construct the exact candidate, validate its authority transitions
and whole-envelope admission, serialize once, compute its commitment, reserve the
successor independent checkpoint durably, and commit the matching SQLite state.
Keep the existing fail-closed crash rule: reservation without a matching database
commit requires intervention; it never authorizes automatic reseeding. At open,
verify the independent lineage and exact byte/revision commitment before typed
owner reconciliation or automatic custody recovery. A valid seal establishes
original admission provenance, not current peer liveness, completed detach or
permission to resume an uncertain effect. It is not a whole-database MAC and
does not cover compromise of the OS user, wrapping key or both durable copies.

Any future migration must separately version the checkpoint, storage schema and actor
schema. Do not turn ownerless v1/v2 JSON into a verified historical witness by
sealing it on upgrade. Preserve original request/mutation keys and attempts,
ciphertext, tombstones and outstanding 16 MiB credits; legacy native bindings
remain unattributed/unresolved with no activation or guessed terminal owner.
An explicit migration may preserve and quarantine a verified-fit legacy snapshot,
but cannot assert its missing peer provenance. Unknown versions, absent lineage,
unverifiable obligations and overcommit refuse before effects. The interview
would need to choose the supported migration gate and handling of unresolved
legacy work. The selected sprint implements refusal, not this migration.

## Admission and implementation boundaries

Extend actual whole-envelope counting and per-list slot obligations for native
owners/attachments with their distinct 256/4,096 bounds. Keep existing 4 MiB
request and 6 MiB mutation reservations and every old effect credit. Native
admission reserves the actual locked serializer's worst legal success, failure,
uncertainty and retirement shapes before I/O, including private escaping,
generations, credit metadata and the maintenance field's own future width.
Do not reduce old domain-slot obligations to make native registration fit.

Separate unresolved-effect credit from future retained-record/tombstone space.
Resolving registration may release its unused effect credit, but active custody
must still retain bounded space for later detach/retirement metadata. A native
ledger reservation API can cover those immutable-width future fields, analogous
to request/mutation ledgers. Explicit detach uses its own stable operation and
effect credit. Terminal retirement and release share one committed candidate;
the retained tombstone still consumes actual bytes and a lifetime slot. No timeout
releases an uncertain effect credit. The exact composition must be proved before
advertising completion headroom.

Likely implementation files after authorization: new `src/native_owner.zig` for
bounded records/references/structural reservations; `src/snapshot_admission.zig`
for native slots and accounting; `src/domain.zig` and `src/request_authority.zig`
for immutable references without rekeying; `src/engine.zig` for actor admission,
peer reconciliation, removal fences and migration; `src/daemon.zig`,
`src/integrations/native_probe.zig` and platform bridges for internal peer context;
`src/recovery.zig` and `src/storage.zig` for the independent commitment;
`src/integrations/setup.zig` for completion permits. The real Rust broker registry,
ordinary-startup path, app-server handlers, transport peer context and protocol
schemas must produce and enforce the same contract. No isolated advertised stub
is a usable owner integration. Root coordinates all eventual locked Bazel gates.

## Three meaningful acceptance tests

1. Two actual private native processes load the same thread ID. Attach both before
   any acquire; prove exact owner-qualified route isolation. Reject forged JSON
   witness, wrong connected incarnation and replaced/delegated endpoint before
   registration. Safely reject one request, then show presenting its original key
   from another owner cannot reopen work or grant a third attempt. Detaching A
   must preserve B's original route and terminal-report authority.
2. Real SQLite plus the independent authority exercises crashes before effect,
   after effect/lost acknowledgment and after durable completion. Restart retains
   original owners, operations and credits without redispatch. Alter witness,
   attempt history, credit or retirement metadata while preserving the old
   checkpoint tuple: the commitment must refuse before custody effects. Partial
   detach and endpoint absence preserve the removal fence and old terminal-report
   exception; an exact final acknowledgment alone permits retirement.
3. Fill the actual 16 MiB envelope and native/domain record ceilings with legal
   escaped metadata. Registration and detach lacking headroom refuse before
   native effects; already-admitted worst completion and retained tombstone fit
   while unrelated writers preserve their bytes and slots. Cover scalar-width and
   maintenance self-width boundaries, then attempt ownerless/unknown/overcommitted
   migration and verify unchanged ciphertext, original two-attempt history and
   unresolved reservations. Synthetic fits alone establish no live continuity.

Remaining blockers are actual platform
peer/delegation proof, the independently committed original witness boundary,
bounded retained retirement space, and real native producer/protocol behavior.
Implementation requires root's explicit file-owner releases under the selected
sprint; no support promotion follows this R-N13 review note.
