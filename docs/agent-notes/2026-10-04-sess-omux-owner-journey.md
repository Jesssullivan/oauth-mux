---
title: First native owner journey and bounded acceptance review
date: 2026-10-04
status: active
summary: Review of a Linux and versioned Codex owner slice, with startup, pre-acquire attachment, removal and recovery gates kept separate from live continuity.
refs:
  - R-N13
  - ../plans/omux-native-account-lifecycle-reset-2026-10-02.md
  - ../plans/omux-native-owner-custody-next-stage-2026-10-04.md
  - ../product/user-stories.md
  - ../product/support-and-completeness.md
  - ../spec/native-adapter-contract.md
  - ../reliability/service-objectives.md
  - ../governance/repository-roles.md
---

R-N13: root assigned review of the next five-hour native owner and Codex protocol
stage and sole ownership of this note. This is a source and acceptance review,
not an execution receipt or a change to product authority. No runtime, candidate,
shared product document, host, provider, tracker or service action occurred.
Root coordinates all locked Nix/Bazel execution; PZM remains held. R-N11 retains
other sessions and processes. An actual R-N12 guard-hook refusal must be handled
through its stated escalation, rather than bypassed.

The [reset](../plans/omux-native-account-lifecycle-reset-2026-10-02.md) remains
the architecture and product bar. The
[owner proposal](../plans/omux-native-owner-custody-next-stage-2026-10-04.md)
still records proposed details and unimplemented acceptance; root owns any
subsequent ratification, classification or plan changes. This note cannot
silently turn its proposed limits or wire fields into accepted source facts.

## Recommendation and five-hour success boundary

The useful bounded win is a Linux-only owner custody slice across the daemon
and a real, versioned Codex hook: ordinary startup and late attachment register
durable custody before the first acquire; an exact owner can be removed safely;
uncertain registration, partial removal and restart remain fenced. Exercise
that slice through actual private socket and native protocol paths, then obtain
fresh production-build, schema and isolated installed-Linux receipts where the
root-authorized graph can complete them. Do not broaden the slice to Darwin,
refresh adoption, provider login, process-exit retirement or live handoff.

An owner being available means only that the reviewed native instance and
thread attachment have the required local authority. It does not establish a
verified account, compatible grant, provider entitlement, resource capacity,
portable request context or live continuity. Installation, owner admission,
request eligibility and same-process handoff need separate outcomes.

Five hours is enough to aim for one complete, reviewed local slice and its
failure paths. It is not a defensible deadline for product completeness or
support promotion. The critical path crosses peer provenance, Rust startup,
daemon persistence, schema exports, migration and fresh validation. Freeze the
wire and custody contracts early; reserve the final portion for root-coordinated
proof and source correspondence. If those prerequisites cannot be reviewed or
executed, finish with truthful unavailable/unresolved behavior and an exact
blocked-gate record. A table implemented only in the daemon is incomplete.

| Portion of the window | Concrete review or deliverable | Exit condition |
| --- | --- | --- |
| First 45 minutes | Agree the negotiated capability, Linux peer/incarnation evidence, acknowledgment tuple, durable phases, removal fence and migration policy. | Root-reviewed contract; exact source ownership; no effects authorized by JSON PID or configuration alone. |
| Next 105 minutes | Implement the daemon and native producers together, including ordinary startup and loaded-thread attachment before any acquire. Prepare schema/export reconciliation and focused checks. | One coherent candidate epoch with pending-before-effect custody and exact acknowledgments; missing proof fails closed. |
| Next 60 minutes | Review and exercise same-thread/two-process isolation, removal races, lost acknowledgments and restart/migration refusal. Begin production compilation as soon as source is coherent. | Actual-path predicates protect original work, configuration, generations and completion reservations. |
| Final 90 minutes | Freeze source; root runs matching-input runtime/native/build/schema and scoped installed-Linux checks; reconcile artifacts and limitations. | Receipts identify exact bytes, executed versus cached gates, environment and unrun work. No inherited proof or support promotion. |

These portions are coordination recommendations, not performance promises or
permission for this workstream to execute actions independently.

## Inspected baseline and gaps

The [admission evidence](../implementation/native-admission-evidence-2026-10-04.md)
records its own foundation/build and actual-path epochs. Its passing predicates
do not establish new native ownership. Current baseline source inspected for
this review includes [native probing](../../src/integrations/native_probe.zig),
[Codex protocol helpers](../../src/integrations/codex.zig),
[the actor](../../src/engine.zig),
[request authority](../../src/request_authority.zig) and
[capability claims](../../src/catalog.zig).

The baseline native broker version is 1. Its registration identifies a thread
and binding but lacks the proposed owner/incarnation/endpoint/attachment tuple.
Linux probing reads `SO_PEERCRED` and checks UID; Darwin uses `getpeereid`.
Same-user identity alone is not process-incarnation proof. Baseline binding
identity combines application, native session and external binding, without an
owner dimension. The request key is application/session/original request ID and
the original two-attempt budget is already durable.

The [candidate](../../integrations/codex-upstream/README.md) is version-bound,
experimental and unshipped. Its preceding compile and focused broker receipts
remain preceding evidence. New owner bytes require a new inventory, patch/export
correspondence and applicable production/native checks. Stock Codex lacks the
required hook; `native_support: false` and unavailable live continuity remain
the claim boundary. Concurrent source changes must be reviewed against their
own frozen epoch before these baseline observations become implementation claims.

Read-only native workstream review identified a critical ordinary-startup gap,
confirmed against the pinned candidate source. `core/src/session/session.rs`
calls `.with_auth_broker_config(...)` during native session construction;
`app-server/src/in_process.rs` explicitly replaces socket/stdio transport with
bounded in-memory channels. Ordinary TUI uses that embedded path. It needs a
genuine same-process endpoint and owner admission before managed activation and
the first acquire. A separately launched app-server sharing configuration or a
nonce cannot provide peer evidence for the TUI process. A standalone app-server
owner demo leaves the ordinary TUI entrypoint gate open.

The proposed version-2 tuple from the native/runtime review is an opaque owner
ID and process nonce, endpoint/thread-instance/attachment generations, adapter
epoch, and stable registration/detach operation ID with exact acknowledgments.
These remain proposed fields until root freezes the wire agreement. Inspection
of `core/src/client.rs` confirms one request UUID allocated before the current
two-attempt broker loop, with an `Arc` retaining the binding. New owner metadata
must remain immutable through that loop. No reviewed native process-restart
producer restores the original logical request ID; accepted/uncertain work
cannot be continued by manufacturing a fresh UUID after restart or resume.
Native session resume for new user work must still preserve the native store,
safe context and prior fences; it does not grant continuation of unfinished
accepted or uncertain work. These two gates need separate observations.

## Journey and edge-case acceptance

The rows below define desired predicates. Their existence is not a passed gate.
Use the owner proposal's NO-* names as proposed trace labels and retain the
existing US/SC/NAC acceptance meanings.

| Journey or edge | Required observable predicate | Authority and proof boundary |
| --- | --- | --- |
| Install and authorize once | Reversible setup preserves native stores and user edits. Show daemon/vault readiness, native capability and source authorization independently. Do not collect factors or infer enrollment from an owner. | US-INSTALL-01, US-SOURCE-01; SC-01–03; NAC-001–002. An archive, config entry or owner handshake alone proves none of the other states. |
| Ordinary startup | Ordinary native commands and native resume follow the reviewed owner path. Persist pending registration and bounded outcomes before managed activation, even with zero request history. Acquire/materialize must not precede admission. Missing/old hooks or unverifiable peer evidence produce explicit refusal without falling through to a fabricated managed mode. | US-LAUNCH-01; SC-04; NAC-001–002; proposed NO-EARLY/NO-PEER. A startup config read or shared application capability is insufficient owner evidence. |
| Late attach before first acquire | A loaded idle portable native thread can be attached through the same owner contract. Drain or retain ancillary authorization; reject active/opaque contexts. Removal must find that attachment even though no lease, grant route or request ledger entry exists. | US-ATTACH-01; SC-05; NAC-003/010; proposed NO-EARLY. Existing attachment is a separate claim from future-launch setup. |
| Two processes loading one native thread | Distinct verified owners and exact attachment generations keep separate routes, materialization, status and releases. Detaching A cannot detach B or clear B's state. Both still present the original global application/session/request key for the same work; owner changes cannot create a fresh attempt namespace. | US-IDENTITY-01, US-NOREPLAY-01; NAC-004/008–009; proposed NO-ISOLATION/NO-WORK. Real private endpoints/processes are stronger evidence than two invented owner IDs. |
| Stale or mismatched acknowledgment | Registration/detach replies match owner, native incarnation, endpoint, adapter epoch, thread, attachment generation and stable operation. Wrong, delayed, duplicate or retired-generation replies cannot activate a new attachment or release its predecessor's custody. | NAC-002/014; proposed NO-ACK. Reply correlation and a boolean success alone are insufficient. |
| Disconnect races and partial removal | Persist the removal admission fence before native effects. Exclude new owners, attachments and leases while retained accepted work can report terminal state under original authority. Enumerate retained owners, including pre-acquire and unresolved ones. Successfully detaching A does not imply B detached. Restore owned configuration and retire the shared capability only after every required acknowledgment and request fence is resolved. | US-REMOVE-01, US-OUTAGE-01; SC-08/10; NAC-013–016; proposed NO-REMOVE. An unfinished removal is visibly pending, not successful restoration. |
| Unreachable owner or replaced endpoint | Absence, a missing directory, a reused PID, a replacement socket at the same path, timeout or transport EOF cannot prove detach or owner retirement. Retain typed witness, outcome space, configuration and uncertainty; report the bounded missing capability or pending outcome. No process signaling or automatic exit retirement is part of this slice. | US-REMOVE-01, US-REPAIR-01; NAC-014/016; proposed NO-PEER/NO-REMOVE. Reachability and identity are independent. |
| Daemon restart and response loss | Retain original operation IDs, work keys, attempts, owner witnesses, tombstones, credits and ciphertext. Recovered phases are unverified/unresolved until their own proof permits authority. Do not redispatch an uncertain native effect from retained phase alone. A proven surviving owner may have scoped terminal-report authority; it cannot manufacture replacement work. | US-OUTAGE-01; SC-08; NAC-008/013; proposed NO-CRASH/NO-WORK. Native process-restart continuation needs a separate retained-work contract. |
| Upgrade and legacy migration | Validate owned replacement bytes and a versioned migration before effects. Preserve native stores, grant ciphertext, original requests/attempts and mutation IDs. Ownerless legacy bindings remain unresolved; today's endpoint cannot supply yesterday's owner. Unknown, unverifiable or overcommitted obligations refuse conversion without custody loss. Rollback must not resurrect spent authority. | US-INSTALL-01, US-OUTAGE-01; SC-09; NAC-008/016; proposed NO-MIGRATION. Installation rollback is separate from uninterrupted live upgrade. |
| Metadata and owner capacity pressure | Admit worst-case registration/detach/uncertainty/retirement outcomes and their list slots in the production 16 MiB envelope before native effects. Other writers leave reserved outcomes completable. Count live, unresolved and retired authority; no TTL eviction or tombstone deletion makes space. Released bytes never replenish the original two attempts. | US-LOCAL-ADMISSION-01; SC-07/08/10; REL-002/004; proposed NO-CAPACITY. Healthy custody and individual ledger headroom cannot prove full admission. |

Account source disconnect, native attachment detach, integration removal,
account forget and upstream revoke retain their separate meanings. An owner
retirement tombstone prevents old native authority from returning; it does not
revoke a provider grant or replace an account re-enrollment tombstone. Closing
a thin control client still leaves the daemon running.

## Review priorities before release to implementation or proof

1. Verify the producer as well as the consumer. OS-derived incoming adapter
   evidence and the daemon's native control peer must identify the same reviewed
   incarnation. A native nonce, claimed PID, private path or shared capability
   alone cannot establish it. Retain the verified connection or reverify the
   saved exact incarnation and endpoint on every fresh connection. Unsupported
   Linux proof and Darwin owner admission must remain explicit refusal.
   Include the ordinary embedded TUI producer in that review; publish its
   control endpoint in the same native process before owner activation. Check
   startup ordering for thread publication, admission and the first acquire.
2. Review recovery trust separately from structural validity. Current custody
   does not MAC the entire metadata JSON. Self-consistent mutable fields cannot
   invent a verified owner after restart. Approve a concrete provenance and
   installation/checkpoint binding rule, or preserve unresolved state without
   restoring owner authority. Do not call typed private JSON authenticated.
3. Register ordinary startup and late attachment before any acquire. Retained
   owner custody must include threads which have never issued work. An acquire
   side effect cannot be the first evidence that removal needs to find an owner.
4. Namespace route ownership while preserving the existing work namespace.
   The owner/attachment constraint is immutable intent authority, not a new key
   for retry accounting. Owner replacement, daemon epochs, upgrades and native
   resume cannot grant a third attempt or reopen accepted/unknown work.
5. Preserve the pending removal fence and no-resume fence across failures.
   Registration, detach and their acknowledgments need stable operations and
   durable bounded outcomes before effects. Native I/O must not hold the actor
   while synchronously calling back into that actor. Configuration restoration
   waits for all required owners, not merely the currently advertised endpoint.

## Appropriate evidence and five-hour exit record

Root should retain separate receipts for runtime state/credit/migration tests,
actual Linux private-peer/process tests, native core/app-server/transport protocol
tests, generated schemas and artifact/source inventory. Model IDs or fake PID
fields cannot substitute for OS peer tests. Native conformance must exercise the
actual startup producer and pre-acquire late attach, not only a test-only owner
insertion or manual call to the daemon.

Rebuild the changed candidate's production targets through its declared locked
graph, including core, app-server, config, protocol, TUI, CLI, config-schema and
PublicSchema. Record inherent schema helper actions separately from ordinary
tests. A focused library pass does not show that the ordinary native executable
links or that all exported protocol artifacts match. Preserve previous artifact
epochs; unchanged digest-addressed actions may be reused only when inputs match.

A scoped installed-Linux gate must identify the actual relocated artifact,
daemon/native builds, private vault/socket environment, process evidence and
per-user ownership/restoration records. Closing controls must leave the intended
daemon alive. Private generated identities/providers and fake native peers remain
synthetic predicates; a genuine isolated vault or production daemon receipt
does not turn those inputs into live-provider evidence. No personal session,
host service activation or provider access is implied by this note.

At the five-hour checkpoint, report each edge row as implemented, executed,
failed, unrun or explicitly unavailable, with source epoch and limitations.
Owner availability is a local capability result. The support tuple still
requires exact OS/artifact/native version, source/grant/resource scope and
ordinary-launch/resume/attachment mode. SC-06 and NAC-018 additionally require
real provider-originated pre-acceptance rejection, compatible alternate
admission, unchanged native process/session/history/tools/approvals and no
routine handoff prompt. None is earned by owner registration or compilation.

REL-001/002/007/008 measurements retain their own denominators and boundaries.
Fixture durations, owner counts and successful startup are not achieved SLOs,
an availability baseline or a staffed support promise. The private 16 MiB
checkpoint and public 1 MiB frames remain separate limits; redacted owner status
must be bounded, and this review does not claim paginated UI delivery.

Runtime/native reviewers retain their distinct repository duties under
[repository roles](../governance/repository-roles.md). Only public generated
metadata and evidence references flow to the separate SPA. Changed schemas,
site rendering, local archives and a review note cannot create shipped support,
upstream acceptance, publication permission or tracker authority.

## Review result

Recommended scoped success: a coherent experimental Linux/native-owner slice
with actual pre-acquire registration, isolation and bounded removal/recovery
proof, matching candidate artifacts, and honest installed-Linux limits. Unproved
peer provenance, recovery authority, wire agreement or migration obligations
block activation of their affected path. Provider/live continuity, stock Codex
support, Darwin ownership and automatic retirement remain separate unrun gates.

This review performed file inspection only. No test, build, generator, package,
executable check, OS probe, signal or provider request was run. Root owns the
next implementation release and all validation receipts.

## R-N13 released public-fact reconciliation

Root released the catalog handshake limitation, integration-discovery summary,
native-adapter contract, documentation index and the preserved candidate's
tool-profile paragraph for this workstream. Current facts distinguish the
authenticated owner V2 packet endpoint from protocol-1 WebSocket inspection.
The owner capability envelope uses protocol 2 while its nested hook schema
intentionally retains protocol 1. Source review found the actual Rust typed
serialization matches the strict Zig consumer's field names and types.

The producer creates a per-process private owner socket. The consumer's default
advertised path still names the legacy WebSocket endpoint, so an explicit
authenticated owner endpoint remains required. This correction changes no
advertisement or default path and claims no automatic discovery, ordinary
launch/resume, installed Rust or live support. Read-only capability and reserved
thread-generation metadata cannot grant custody.

The preserved `4a236...`/107-file artifact, its eleven-tool receipts and all
historical test counts remain unchanged. The current thirteen-tool manifest
and separate owner candidate require their own artifact/schema/producer
receipts. Root owns reference regeneration and declared SPA import; no bundle
JSON was edited. This workstream ran no executable validation or provider IO.
