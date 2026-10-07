---
title: Native owner request and reliability review
date: 2026-10-04
status: review
summary: Preserve original request authority through bounded native owner registration, removal and restart; actual peer and protocol fixtures remain required.
refs:
  - R-N11
  - R-N12
  - R-N13
---

R-N13 authorizes this assigned review-note mutation for the user-selected next
five-hour native owner/Codex protocol stage. Root owns the exact sprint window,
execution receipts, BUILD changes and installed Linux authorization. This note
changes no runtime, product contract, fixture or tracker. Work was limited to
repository inspection and this note; no build, test, generator, OS probe,
host/service action or provider request was run. The isolated Linux installed lane and protocol proof are separate;
PZM remains held under root's coordination.

The [owner proposal](../plans/omux-native-owner-custody-next-stage-2026-10-04.md)
is the reviewed design input. Its historical candidate receipts do not prove
new owner protocol bytes. The [native reset](../plans/omux-native-account-lifecycle-reset-2026-10-02.md)
remains the product architecture. Proposed owner capabilities are not shipped
support, and stock Codex cannot inherit a compatible-owner claim from fixtures.

## Existing request authority which must survive

[Request authority](../../src/request_authority.zig) keys work exactly by
`(application, session_id, request_id)`. The current immutable intent also pins
`binding_id` and `demand_fingerprint`. `checkIntent` refuses changed intent before
considering an alternate; only an explicitly safely rejected primary permits
attempt two. A second attempt, accepted/completed/abandoned work, and uncertainty
cannot be reacquired. A safe rejection requires pre-acceptance evidence, no
response start, and status 401, 403 or 429. Transport uncertainty is insufficient.

`recoverAfterRestart` changes issued or accepted attempts to unknown while
retaining accepted-report evidence, original handles, issue sequences and the
two-attempt history. Completion remains possible when acceptance was durably
recorded; unknown work without that evidence cannot claim completion or safe
rejection. Explicit abandonment may end its resource fence without authorizing
another attempt. Duplicate accepted and terminal acknowledgments are retained.
No expiry, owner release, account forget, grant rotation, daemon restart or
metadata-space release replenishes this work's attempt budget.

Add verified owner and exact thread/attachment generations as immutable intent
constraints. **Do not add them to the work key.** Otherwise a new owner becomes
a fresh namespace for accepted or already twice-attempted work. A different owner
must fail even when the first attempt was safely rejected. Route binding identity
may include owner/generation for isolation, but the same original work must still
find its retained request record and fail mismatched binding/owner intent. Do not
rewrite legacy request IDs or old binding digests to make a migration fit.

Current coverage is useful but narrower than the proposed boundary:

- [Request ledger tests](../../src/request_authority.zig) exercise immutable
  intent, two attempts, duplicate reports, lost acceptance, serializer bounds
  and issue ordering through restoration.
- [Actual actor acceptance](../../src/engine_acceptance.zig) includes retained
  accepted/unreported work after SQLite restart, changed-binding rejection,
  unsafe-replay refusal and stale/current release fences.
- [Actual envelope adapter tests](../../src/snapshot_adapter_tests.zig) exercise
  saturated acquisition, terminal reports using held credits, unknown work,
  duplicate acknowledgments and two restarts without restoring attempt budgets.
  These direct actor requests use a shared application capability. They do not
  establish OS-derived owner attribution or native process identity.

These are source observations and existing test scope, not new execution receipts.

## Concrete owner integration seams

[Daemon ingress](../../src/daemon.zig) currently verifies the peer user and passes
channel/payload/deadline to engine dispatch. It does not carry a process witness
to the actor. [Native probing](../../src/integrations/native_probe.zig) verifies
protected paths/user identity but attachment and detachment use separate newly
opened connections. Existing registration acknowledges binding and refresh
ownership; existing unregister acknowledges a boolean. Neither establishes the
new owner/endpoint/attachment generation tuple.

The owner extension needs typed connection evidence from socket acceptance,
owned until the actor has finished the invocation. A JSON PID, nonce, socket
path, owner handle or shared application capability cannot substitute for that
evidence. The proposed Linux process-handle profile requires its own declared
actual-OS proof; this review does not establish API/kernel availability. Missing
or unsupported peer proof must refuse before effects. A fixture in which two
native endpoints are threads in one test process cannot prove process isolation.

In [engine report handling](../../src/engine.zig), `requests.checkReport` currently
can return a duplicate acknowledgment before `nativeLease` checking. The unknown
restart completion/abandonment and accepted restart-completion paths also allow
terminal reports without a process-local lease. **Validate the exact retained
owner, thread generation and verified ingress peer before every such branch.**
An owner mismatch must neither acknowledge another owner's report nor release
its credit. These branches must remain available to the genuinely authorized
surviving owner; requiring fresh acquisition to report would break the original
accepted-work fence. Metadata, materialization and release need equivalent scope
checks. A stale owner cannot act on the newest route merely because it knows an
older handle, and an idempotent duplicate still requires attribution.

Removal must not retire a shared capability epoch before legitimate scoped
terminal-report authority is usable. Separate permission to complete already
admitted work from permission to acquire/materialize/register new work. The
exact surviving-owner proof and any post-restart reconciliation mechanism need
review; a retained owner phase alone confers no fresh transport authority.

## Registration, removal and bounded uncertainty

Before a native registration or detach is issued, persist the original stable
operation ID, typed witness, immutable generations, pending phase and maximum
completion/uncertainty/retirement byte and slot obligations in the whole 16 MiB
envelope. Count live, unresolved and retired owners together. The proposal's
256-owner and 4,096-attachment/retirement ceilings require explicit typed ledger
limits; the existing domain's 1,024-record ceiling is not automatically their
implementation. Actual serializer measurement must include all new sections,
credit metadata, status/generation widening and removal tombstones.

Registration which reaches native managed activation but loses its reply remains
unresolved, including a thread which has never acquired a credential. No request
or binding census can stand in for the owner census. A wrong or late tuple cannot
activate an owner or return its credits. Registration retries use the original
registration operation and its own idempotency contract; they never allocate a
new model work UUID. Restoring a phase, observing no endpoint or releasing a
credit cannot authorize reissuing an uncertain effect.

Persist removal admission fencing before enumerating or contacting retained
owners. Refuse new owner/attachment/lease admission after that fence. Partial
detach, unreachable/replaced endpoints, unsafe native context and ambiguous
acknowledgments retain the corresponding obligations and configuration. Finish
restoration and capability retirement only after all required exact-owner
acknowledgments and accepted-work/lease fences resolve. No TTL or absence-based
eviction is acceptable. Delayed acknowledgments must match their original
operation and generation and cannot consume another reservation.

Restart preserves original operation IDs, request attempts, accepted evidence,
credits and retirement fences while peer ownership becomes unverified or
unresolved. Current metadata validation and checkpoint lineage do not MAC all
metadata JSON. A self-consistent owner row cannot invent an authenticated peer
witness. Any migration or recovery authority must fail closed until its trusted
attribution/seal design is separately established; do not infer legacy ownership
from today's socket or silently discard/rekey ownerless requests.

Native I/O must not block the single writer waiting for a synchronous callback
into that same writer. Registration/removal continuations need bounded work,
stable owned inputs and exact original-operation correlation. Daemon and adapter
timeouts are uncertainty, not proof that a native mutation did not happen.

## Meaningful actual fixture priorities on release

Root coordinates all executable proof through locked Nix/Bazel. The following
are intended acceptance predicates, not passing tests or new deadlines:

| Fixture | Actual stimulus and required observations |
| --- | --- |
| Two real native processes | Declared child-process fixtures publish independent private sockets with the same thread ID. Verify ingress/control peer correlation through actual OS sockets, register A and B, acquire distinct original work, and detach A. B's owner generation, route and allowed materialization remain intact. Swapping claimed JSON owner/PID fields must not substitute the peer. |
| Positive peer control and endpoint replacement | First show the same actual peer and negotiated tuple can register. Replace the socket publication at the identical pathname with another process/endpoint generation; stale attach/detach/metadata/materialization/report/release refuse. A missing required process-handle feature refuses without pretending that a numeric PID is equivalent. |
| No-acquire registration custody | Observe the native registration effect but lose its reply before any acquire. Crash/reopen the real private SQLite actor. The pending owner and credits remain, effect count does not increase, and removal cannot conclude from an empty request list. A delayed mismatched acknowledgment changes neither state nor another credit. |
| Accepted and unknown work across owners | Through actual daemon framing/peer context, owner A issues original work and either reports acceptance or loses that report. After daemon restart/removal, matching A may deliver only permitted terminal/duplicate reports; B using the same session/request/handle must fail before any counter, credit or route mutation. Original work remains non-reacquirable. |
| One safe alternate, unchanged namespace | A safely rejects attempt one. B presents the same original session/request and must receive owner/intent mismatch without issuing attempt two. Matching A may consume its single alternate. After another rejection, registration retry, owner replacement and two daemon restarts, a third attempt remains refused. Assert request-record count and attempt sequence, not only an error string. |
| Removal races and partial acknowledgment | Commit the real removal fence, then interleave registration/acquire with native detach callbacks. New admissions refuse; original accepted terminal reports remain scoped and usable. Only correctly acknowledged owners retire. A replacement endpoint or wrong generation cannot finish restoration or advance the shared epoch. |
| Actual capacity rollback | Fill real non-ledger metadata and owner/retirement slots at their production ceilings while another owner's completion is reserved. Oversized registration/removal refuses before native effect; exact stored snapshot digest/revision, ciphertext, original owner/work generations and credits remain unchanged. Previously admitted exact completion can still commit atomically. |
| Crash matrix | Private subprocess fixtures stop only their own declared test processes at before-effect, after-effect, after-ack and before/after-commit boundaries. Reopen storage and use actual socket callbacks/counters to prove no duplicate native registration/detach/model execution and no automatic retirement. Repeated uncertainty consumes no new original work budget. |

Use the real daemon/socket framing and peer-to-actor path for owner predicates;
direct `Engine.dispatch` can supplement writer/replay checks but cannot prove
OS attribution. Native responders must implement the negotiated protocol under
test and include a positive control, not simply copy an expected owner ID into a
daemon-only fixture. Synthetic credentials are generated in private test roots,
encrypted before SQLite writes, and never logged. Provider submission tripwires
stop before HTTP. Installed Linux artifact predicates remain separately labeled
from these fixture and patched-Codex protocol predicates. Native-live ordinary
launch/resume/same-process handoff and history preservation need their own exact
application/source/artifact receipts.

## Diagnostic and SLO scope

Preserve diagnostic `.bad` counting and the original request denominator rules.
The appended `local_capacity` and `result_bound` causes identify a bound, not the
phase or whether admission was already promised. Phase attribution and SLO
eligibility accounting remain unimplemented in the current recorder.

Future owner diagnostics need a bounded phase/evidence classification established
by the actor: pre-admission safe refusal, admitted pending native effect,
uncertain effect/ack, and failed promised completion. Do not classify these using
only an error name, caller-provided phase or fixture success. Such classification
must retain user-impact/readiness reporting and cannot reinterpret all capacity
errors as good/excluded work to improve availability.

The [service objectives](../reliability/service-objectives.md) retain their exact
targets and budgets. REL-002 requires a verified native hook, valid alternative,
known required capacity and durable completion headroom for eligible admission;
missing owner/native capability or headroom remains a separately reported
readiness deficiency. REL-003 has zero integrity budget for restart, routine
prompt, native-state loss or accepted-work/tool replay. REL-004 has zero custody
budget; a safe admission refusal must preserve retained secrets and fences.
REL-005/REL-007 can count a timely truthful actionable terminal refusal under
their specified denominators without calling it successful enrollment or
restoration. Failure of an already-admitted reserved outcome is a different
failure requiring investigation, not an eligibility rewrite.

Current latency begins at engine dispatch and omits daemon ingress/worker queues,
framing and flushing. Histories reset on restart and have no independent scheduled
coverage or exact native/artifact provenance denominator. Actual OS fixtures,
protocol checks and installed Linux receipts do not establish a measured baseline,
achieved SLO, staffed support, contractual SLA or live continuity.

## Request implementation checkpoint

R-N13 ownership covers `src/request_authority.zig` and
`src/native_owner_request_tests.zig`. Immutable optional `Intent.native_ref`
preserves the original application/session/request key and two-attempt budget.
Owner-aware report preflight and mutation check the exact retained reference
before duplicate or restart-terminal transitions. Historical null references
remain fences and cannot grant native report authority. Immutable reference
serialization is counted in the request partition reservation.

Root gate `47f04156` passed the earlier four ledger-case input. The current
seven-case file adds three prepared actor cases using genuine current-process
packet evidence: encrypted materialization/no-peer refusal; original terminal
report after `Engine.restart` without registration or acquire; owner mismatch
before a safe alternate; and accepted work under actual pending removal with
retained configuration/capability and original terminal-report custody. These
actor cases still require a passing current-source gate. Two opaque owners in
one fixture process do not establish distinct-process OS isolation, and direct
engine restoration does not prove reconnection to a replaced daemon process.

Root compile feedback `392eae1d` found the test diagnostic loop's unbraced
assignment. The narrow correction adds braces and an explicit `anyerror!Reply`
for the recursively health-reading RPC helper. Production request authority is
unchanged by this correction. The owned test file is refrozen; no independent
execution was performed and the failed compile is not an actor proof.

Actual full-suite feedback `cb6a` reached registration refusal in request case
five and a stack-address segmentation fault in case six. The direct request
`Actor` now uses an exclusively created 0700 short private root, with an owned
sentinel path and retained directory descriptor. Cleanup opens the exact root
without aliases and compares original/current device and inode before deleting
only its tree. The real broker socket limit is unchanged. Restart and teardown
clear the optional engine pointer before closing; original native references are
retained without re-registration.

Read-only lifetime review found no demonstrated additional borrower defect in
the owned request helper: inserted JSON keys and operation values are owned by
the parsed arena, revision is a scalar, and producer cleanup joins workers while
the engine remains alive. A stack address alone does not establish the cause of
case six's abort. The short-root correction is refrozen without independent
execution; a focused root gate must establish whether the abort is resolved.
