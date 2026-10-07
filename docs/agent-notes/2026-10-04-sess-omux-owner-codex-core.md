---
title: Codex core native owner producer review
date: 2026-10-04
status: review
summary: Pinned core review and isolated owner-v2 implementation record the real constructor fence, immutable requests, verified daemon pin, native task lifetime custody and fresh unrun proof gates.
refs:
  - TIN-2057
  - R-N11
  - R-N12
  - R-N13
  - R-C227
---

R-N13: root authorized the initial durable review note for the user-selected native
owner custody and Codex protocol sprint. This mutation changes documentation
only. No Rust, Omux runtime, candidate manifest, patch or historical receipt is
changed; no build, test, executable, host, provider or upstream action was run
for that review. Root owns classification and the new isolated candidate epoch.

The [owner proposal](../plans/omux-native-owner-custody-next-stage-2026-10-04.md)
records the proposed acceptance boundary. This note supplies concrete source
locations and implementation ordering; it does not turn a proposed wire method,
platform profile or installed/live gate into support. Stock Codex still lacks
the required hook. The existing candidate's compile and inventory receipts
cannot prove a changed owner protocol.

## Immutable source inspected

Source root:
`/srv/fast-local/jess/state/codex/omux-codex-source-00c972ed/source`.
Official base commit `00c972ed5d6ff6499317fd41b7f23605b8e6850d`,
tag `rust-v0.157.0`; product patch SHA256
`4a236da5663485458744375f8844898682d4b9f160fd37c00e912fd7cd2e76c3`.
Root must preserve these bytes and restore a separate complete candidate before
authorizing Rust edits. Line locations below refer to this inspected candidate.

| Path under the source root | Implemented predicate and gap |
| --- | --- |
| `codex-rs/core/src/auth_broker.rs:27` | Protocol version is 1; six capabilities name late binding, request authorization, refresh ownership, proven rejection, transport invalidation and native context reconstruction. None advertises durable owner identity. |
| `codex-rs/core/src/auth_broker.rs:59` | Process-local registry maps `ThreadId` to `Arc<BrokerBinding>`, plus detached markers and ancillary activity counts. It has no incarnation, thread-instance generation, operation or pending owner phase. |
| `codex-rs/core/src/auth_broker.rs:211` | `register` verifies private socket/capability and drained ancillary activity, then inserts/replaces a local binding. It never registers daemon custody. |
| `codex-rs/core/src/auth_broker.rs:81` | `unregister` removes by thread ID; asynchronous binding release requires a last lease. A registered thread with no acquire has no daemon release callback. `forget` clears the local reentry marker. Neither is an exact owner disconnect acknowledgment. |
| `codex-rs/core/src/auth_broker.rs:475` | Each adapter RPC opens a new Unix connection and checks broker peer UID. It carries shared capability/application but no immutable owner tuple or per-writer OS evidence. |
| `codex-rs/core/src/client.rs:562` | `with_auth_broker_config` calls the local register using the native thread ID as binding ID. Successful configuration reading is not daemon admission. |
| `codex-rs/core/src/session/session.rs:1739` | The configured registration occurs inside session construction, before the loaded thread is published by its manager. |
| `codex-rs/core/src/thread_manager.rs:2342` | `finalize_thread_spawn` inserts the actual `Arc<CodexThread>` only after `SessionConfigured`; the caller then emits ready/resume lifecycle and returns the thread. This is the proposed post-publication/pre-exposure owner fence. |
| `codex-rs/core/src/client.rs:1638` | One request UUID is allocated before the two-attempt loop. The request snapshots its binding; account substitution resets transport affinity while preserving native input and thread/turn metadata. |
| `codex-rs/core/src/client.rs:1751` | Header acceptance reports accepted, returns the stream and never retries SSE/tool/EOF failures. Completion disarms cleanup only after recorded terminal acknowledgment. |
| `codex-rs/core/src/responses_retry.rs:61` | The outer response retry handler refuses resampling while the broker replay fence is set. |
| `codex-rs/tui/src/lib.rs:279` | Ordinary terminal startup may use `InProcessAppServerClient`; an explicitly separate server is not required by the native application. |
| `codex-rs/app-server/src/in_process.rs:431` | Embedded startup uses an in-memory router and processor. It does not publish the native Unix control endpoint needed by this profile. |
| `codex-rs/app-server/src/message_processor.rs:964` | Initialized requests enter queued serialization or spawned handlers. The outer in-process loop's await alone does not prove a current callback deadlock. The new handshake must avoid a shared serialization scope or held lock. |
| `codex-rs/app-server/src/lib.rs:787` | Existing main-server Unix control acceptance is selected by `AppServerTransport::UnixSocket`. Adding owner fields here alone cannot cover embedded ordinary startup. |

## Complete producer boundary proposed for review

The core, lifecycle and protocol reviewers agree on an early process-private
native endpoint and a post-publication/pre-exposure startup fence. A server in
another process cannot supply the control witness for the process issuing core
adapter requests, even if both read the same config or nonce. Embedded and
standalone app-server startup need the same producer service in their actual
process. Unsupported direct core consumers must refuse managed activation until
they have this producer; no launcher or intercepted session is introduced.

The process owns one random process nonce and endpoint generation. These enter
core from the real startup service, rather than being generated independently by
each model client. Loading a new native thread instance allocates a checked
nonzero generation even when its persisted `ThreadId` matches another instance.
The lifecycle reviewer proposes exact fields: opaque 64-hex `owner_id` and
`process_nonce`, nonzero `u64` adapter epoch, endpoint generation, thread-instance
generation and attachment generation, exact native thread ID, and a stable
registration/detach operation ID. These fields constrain authority; they do not
replace OS peer evidence. Wire spelling, carrier and allocation ownership remain
subject to the final reviewed protocol contract.

The startup sequence needs all of these steps:

1. Publish the verified process-private native endpoint before managed session
   construction. Reserve a pending core thread tuple and block canonical
   authorization/refresh and managed acquire. Configured startup's existing
   local-only discovery and ancillary guards remain active.
2. Construct and internally publish the actual native thread. Before ready or
   resume lifecycle exposure and before returning it to the caller, run owner
   admission through an independent native worker.
3. The daemon verifies that adapter ingress and native control identify the same
   process incarnation, reserves all outcomes and commits pending owner custody
   before native managed activation. It must track threads with zero acquires.
4. The native handler checks the exact prepared tuple, real loaded thread and
   current safe state, then atomically activates that tuple. The acknowledgment
   echoes every immutable field and operation. The daemon commits the exact
   result before acquire becomes usable or startup is exposed.
5. Lost/mismatched acknowledgment or uncertain commit leaves pending/unresolved
   custody and a native readiness fence. It does not fall back to ambient auth,
   infer activation from configuration or start another owner operation.

`SessionConfigured` is an internal event consumed by `finalize_thread_spawn`
before map publication; it cannot stand in for an owner-ready acknowledgment.
Pending readiness must cover direct session submission, background credential
work and the model stream entry from construction onward, including the interval
after internal publication. Only bounded inspection/shutdown may bypass that
work fence. Do not start model requests, tools or externally expose a ready
thread before the exact owner outcome commits. The actual producer test must
try first work on both sides of publication while acknowledgment is withheld.

The independent handler must hold a cloned real `ThreadManager` and owner
registry and use shared bounded native logic directly. Routing a callback through
the same blocked startup serialization scope could create a circular wait;
current dispatch does not establish that every request shares such a scope. Neither a
registry lock nor a thread-map lock may span daemon/native I/O. The serial daemon
actor must also remain available while a bounded native worker runs. A late
attachment consumes already committed prepared authority and responds locally;
it must not synchronously call the waiting daemon actor for metadata or acquire.

The peer reviewers identified an unresolved carrier choice: generic Unix
WebSocket/Tokio reads discard ancillary per-writer credential evidence. An
accept-time peer alone cannot reject a subsequently delegated descriptor.
Their proposed dedicated process-private owner JSON-RPC carrier shares the real
native handler, but requires reviewed bounded credential-aware reads before
framing, including truncation, unexpected descriptor and writer-change refusal.
No current `--listen` WebSocket or claimed PID/nonce is accepted as proof of
that boundary. Exact Linux kernel/libc/API dependencies and the carrier design
must be settled before implementation; Darwin UID-only evidence stays
unsupported for this owner profile. This review performs no OS probe.

## Native concurrency, detach and original work

Registration must reserve pending state under the same lock used by ancillary
activity guards, then release the lock before awaiting admission. Pending,
active and unresolved states all block new ambient work. `stream` must explicitly
refuse pending/unresolved state; an absent active binding must not silently enter
the native-auth branch. Startup failure after publication may retire custody only
with durable acknowledged proof that no activation occurred; disappearance of an
`Arc` is insufficient. A conflicting registration cannot replace a live tuple;
an exact duplicate operation may return only its original recorded outcome.

Loaded-status and agent-idle checks precede the current late attach/detach logic.
The new commit additionally needs an atomic native transition fence against
turn starts, managed stream activity and ancillary activity. A prior idle
observation alone cannot authorize a later detach. Preserve analytics shutdown,
local-only plugins, MCP authority drain, process-global/thread ambient guard
checks, descriptive model mode and opaque-context restrictions. Owner fields
do not weaken those checks or transfer refresh ownership back to native code.

Store the immutable owner tuple in each `BrokerBinding`. A request and its
`LeaseGuard` retain their original `Arc`, UUID and tuple even when the registry
changes. Acquire, metadata, materialize, report and release must carry and verify
the appropriate original scope. Detachment blocks replacement acquisition while
retaining exact outstanding terminal-report authority; old-generation report
permission does not imply fresh materialization or a new attempt.

Core unregister must compare the complete retained tuple and operation before
removal, retain an exact detached/reentry generation and return its exact
acknowledgment. It cannot retire a zero-acquire owner by finding no last lease.
Thread teardown and local `forget` must not erase daemon unresolved/tombstone
authority or invent process-exit evidence. A native request still rechecks actual
portable input before restoring ambient auth after verified detach.

Keep the daemon work key `(application, native session, original request_id)`.
Owner and thread generations constrain the retained intent and namespace route
bindings; they do not create a second work namespace. The core UUID stays outside
the existing two-attempt loop. Only recorded preacceptance HTTP 401/403/429 may
use the single alternate; accepted, ambiguous, abandoned and uncertain outcomes
retain their fences. HTTP retries, ambient refresh, cookie auth, opaque context
substitution and outer stream resampling remain disabled in this branch.

No inspected producer retains that UUID across native process replacement.
Two processes resuming one native thread need separate owner-scoped routes, but
cannot reopen retained work under a new owner or fresh UUID. Ordinary native
history resume and continuation of an already accepted request are separate
gates. This stage must not advertise process-restart work continuation without a
retained original-work protocol and its own evidence.

## Fresh focused proof plan

The following are proposed tests, not passing counts:

| Focused Rust predicate | Meaningful real path |
| --- | --- |
| Ordinary startup before first acquire | Actual embedded native startup publishes its own endpoint, constructs a native thread, records daemon owner custody with zero acquire RPCs, and refuses exposure/acquire until exact commit acknowledgment. |
| Startup callback progress | Withhold daemon acknowledgment while start-thread waits; the independent native endpoint still answers and native stream refuses. No shared serialization scope or registry lock deadlocks. Uncertainty remains fenced. |
| Tuple and operation checking | Every wrong owner, epoch, nonce and generation refuses; an exact duplicate returns its original result; older operations cannot replace or detach a newer tuple. |
| Ancillary and turn race | Existing process/thread ambient activity, MCP authority or a racing turn start prevents activation/detachment without weakening drain or renewal ownership. |
| Two native instances, same thread ID | Actual private producers have distinct OS incarnation and thread generations; removing A preserves B's binding/materialization and does not alter the original request key. |
| Original request attempts | Actual managed stream sees one UUID for its proven first rejection and only alternate; accepted SSE/EOF/tool/cancellation failures cannot invoke another acquire/HTTP request or tool execution. |
| Zero-acquire and active-stream detach | An owner with no last lease is still tracked. Active-stream/opaque-context detach refuses; wrong/late acknowledgment cannot retire custody. Exact terminal cleanup stays scoped and occurs once. |
| Recovery and compatibility | Retained pending/unresolved operations do not replay after daemon restart; ownerless protocol-1 bindings cannot acquire owner authority by migration or nonce inference. |
| Writer and endpoint identity | Separate OS process/writer, delegated descriptor, replaced endpoint and unsupported peer APIs refuse before owner effect, using the reviewed real carrier. |

Extend the actual `auth_broker` tests using their existing private `MockBroker`
and bounded ordered exchanges. Add real startup/stream tests where core unit
coverage alone cannot exercise the producer. Proposed declared target families
are `//codex-rs/core:core-unit-tests`, `//codex-rs/core:core-all-test`,
`//codex-rs/app-server:app-server-unit-tests`,
`//codex-rs/app-server-transport:app-server-transport-unit-tests`, and
`//codex-rs/app-server-protocol:app-server-protocol-unit-tests`.
Root must select meaningful filters and declared process fixtures after exact
new target inspection. Broad core integration suites include unrelated native
operations; listing a family does not authorize those operations.

The proposed owner hook is protocol version 2 with an explicit negotiated owner
capability. Protocol 1 must report the missing owner capability and refuse owner
admission, never silently synthesize fields or downgrade. Preserve historical
version-1 schema/fixture receipts; changed fields and exporters require a new
candidate artifact epoch and fresh focused protocol/schema proof. Keep exact
native disconnect acknowledgment distinct from asynchronous lease release.

After artifact refresh and full source inventory, compile the historical eight
production labels against the new candidate:

- `//codex-rs/core:core`
- `//codex-rs/app-server:app-server`
- `//codex-rs/config:config`
- `//codex-rs/app-server-protocol:app-server-protocol`
- `//codex-rs/tui:tui`
- `//codex-rs/cli:codex`
- `//codex-rs/config-schema:codex-write-config-schema`
- `//bazel/schema:public-schema-bundle`

Record inherent schema generator actions separately from compiled target counts.
Root coordinates every locked Nix/Bazel invocation and new immutable receipts.
Installed Linux ordinary launch/resume and real process/incarnation proof require
their own exact candidate/kernel/installation evidence. Provider continuity,
native history/tools/approvals preservation and same-process account handoff
remain additional unrun live gates. This source review claims none of them.

## Isolated implementation epoch, pending execution

R-N13: root released the separately restored development source after complete
prepare receipt `fae07b14-502e-4df6-b8f0-10dc06603792`. Its initial source inventory
matched the old candidate; subsequent implementation writes belong only to
`/srv/fast-local/jess/state/codex/omux-codex-owner-development-20261004/source`.
The immutable original source, product patch and eight-target proof remain
unchanged. This section records source implementation and proposed test
predicates, with no inherited compile, installed or live result.

Core-owned changed paths under the development source are:

- `codex-rs/core/src/auth_broker.rs`
- `codex-rs/core/src/auth_broker_owner_tests.rs` (new)
- `codex-rs/core/src/client.rs`
- `codex-rs/core/src/session/session.rs`
- `codex-rs/core/src/session/handlers.rs`
- `codex-rs/core/src/thread_manager.rs`
- `codex-rs/core/src/native_owner_startup_tests.rs` (new)
- `codex-rs/core/src/tasks/mod.rs`

The version-2 producer prepares configured custody before native session auth
or work, publishes the actual `Arc<CodexThread>` internally, then awaits actual
`adapter.owner.register` before emitting ready/resume or returning the thread.
An unconfigured thread allocates actual process-local thread-generation
metadata when the endpoint exists, without adopting Omux or blocking ambient
work. Explicit late attach reserves pending state atomically against ambient,
broker and native-task counters. Malformed input is checked before admission
effects; the authenticated callback checks the pinned daemon peer and complete
tuple before native ancillary drain and repeats the registry check on activation.

Every broker exchange uses the shared verified stream with per-segment writer
evidence, an absolute transport deadline and eight bounded blocking exchange
slots. The producer pins its original daemon witness before sending registration;
callbacks, protected exchanges and cached detach ACKs compare that retained
authority. A replacement daemon is refused; no restart-continuity claim is made.
Protected exchanges carry the exact `NativeRef`, and native thread use is
checked against the original binding. Request UUID allocation remains outside
the unchanged two-attempt loop, with accepted response and outer retry fences
preserved. The whole accepted stream owns a request guard; actual task execution
owns its native-work guard through hooks, tools, terminal completion and
cancellation. Pending, lost or wrong ACK states retain the work fence.

The local thread descriptor returns the actual thread-instance generation and
attached or prospective next attachment generation for the latest known actor
epoch. Unattached listing is diagnostic metadata, never authority for an unknown
future actor epoch. Activation derives the exact reservation from the incoming
validated owner ID, adapter epoch, endpoint generation and thread instance.
Initial reservation is 1; retirement advances only that exact incarnation with
checked arithmetic. A new actor epoch starts at 1 and retains old references.
Actor admission remains authority and must adopt the exact reservation. The
source does not invent a detached owner, silently replace a peer or evict retained
retirement records when its bounded registry fills.

Existing broker fixtures now obtain authority through real private producer
streams and owned sequence-packet activation/retirement, without authority
setters or fabricated peer witnesses. Their expected protected frames include
the actual registered reference. Legacy unregister/forget expectations were
changed: they cannot drop attached or pending version-2 custody; exact native
detach precedes final forget. Expired lease abandonment and accepted-work
non-replay expectations remain intact. Cleanup retires exactly acknowledged
fixture custody and clears only its non-authoritative thread metadata.

Requested fresh gates are `//codex-rs/core:core-unit-tests` filtered separately
to `auth_broker` and
`thread_manager::native_owner_startup_tests`. The new constructor fixture drives
real `ThreadManager::start_thread`, withholds the daemon result after the
producer connects, verifies internal publication and withheld readiness, submits
actual `Op::Compact`, and checks actual task-spawn refusal before its run entry.
A second genuinely unmanaged thread runs a held task through the real dispatcher;
late attach must refuse while its native lifetime guard lives and succeeds only
after actual cancellation completes. Genuine packet callbacks and exact committed
registration results complete both fixtures. The validator case covers canonical
full-u64 decimal generations and lower-case opaque IDs.

The separate genuine retirement regression registers at epoch 1, obtains its
exact native retirement ACK, then registers the same actual thread instance at
epoch 2 with attachment generation 1. Old activation is refused and a duplicate
cached old retirement ACK cannot remove the current binding. Both registrations
use the actual producer stream and packet callback; this fake-daemon epoch test
does not prove real daemon process restart or restart reconciliation.

The root-approved ordinary-unconfigured correction makes metadata preparation
return the explicit `NativeThreadPreparation::Unavailable` outcome when its
bounded capacity or generation is unavailable. A session without configured
broker custody keeps ambient behavior; configured registration still propagates
managed admission refusal. Registry corruption/poison errors propagate rather
than being swallowed. Identify/descriptor refuse unprepared rows, and the
app-server listing refuses its whole result instead of omitting loaded rows.
The focused local metadata predicate fills the exact bounded capacity, preserves
an existing immutable identity, proves unavailable preparation inserts nothing
or advances no generation, and proves managed admission still refuses. It also
covers u64 generation exhaustion without any owner, native reference, binding or
peer witness injection. This boundary predicate is not an executed large-thread
application test or a live continuity claim.

All these tests are source-only and unrun at this note epoch. A private fake
daemon proves neither the Omux actor nor provider continuity. The app-server
lane separately owns actual endpoint, wrong-tuple/wrong-process and pre-drain
discriminators. Root owns formatting, focused execution, the eight production
targets, artifact refresh and exact current-candidate evidence. Stock Codex,
non-Linux custody and live seamless handoff remain unsupported or unproved.

## Typed expected refusal correction, fresh gates pending

R-N13: the embedded positive-control review found a concrete event classification
defect. Actual pending shell-work refusal emitted generic `EventMsg::Error`;
app-server marked the native watch `SystemError`, so its unchanged strict idle
admission rejected the later authorized owner callback. The refusal did not
increment the native-work counter. No idle or unsafe-state gate was weakened.

The narrowly released core/protocol correction adds the known native
`CodexErrorInfo::NativeOwnerPending` wire variant `native_owner_pending`, which
does not affect accepted-turn status or permit guardian retries. A private typed
I/O error payload identifies only actual pending/unresolved native-work refusal.
Submission and both task admission branches classify that payload specifically;
registry/capacity errors remain generic faults with a fixed fault message. A
generic I/O error with the same kind and text cannot obtain expected-refusal
classification. The app-server lane owns exact v2 mapping and direct error
notification before system-fault or turn-summary mutation.

Additional changed existing development paths for pristine artifact custody are
`codex-rs/protocol/src/protocol.rs`,
`codex-rs/protocol/src/codex_error_info.rs` and
`codex-rs/ext/guardian-reviewer/src/retry.rs`. The already owned core
`auth_broker.rs`, `session/handlers.rs` and `tasks/mod.rs` contain the specific
marker and classification changes. Tests add exact native codec roundtrip,
malformed known payload refusal, nonterminal native-history predicate and
marker-versus-generic-fault discrimination. These current-input changes are
unexecuted at this note epoch; previous core/broker passes do not cover them.
