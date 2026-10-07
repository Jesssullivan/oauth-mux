---
title: Native owner custody independent security review
date: 2026-10-04
status: active_source_review
summary: Review the complete native owner protocol, trusted recovery attribution, scoped credential access and irreversible removal boundaries without inheriting live proof.
refs:
  - R-N11
  - R-N12
  - R-N13
---

R-N13: root assigned this note and independent review of the user-selected native
owner/Codex protocol implementation and isolated Linux installed checkpoint.
Only this note is writable in this lane. No implementation, executable proof,
host, provider, service or tracker action is performed by the reviewer. Root owns
locked Nix/Bazel proof batches. PZM remains GF-held. This note records source and
design review, not passing acceptance or supported native continuity.

The [owner proposal](../plans/omux-native-owner-custody-next-stage-2026-10-04.md)
remains explicitly unimplemented/unratified until its new implementation and
current-input gates pass. Prior admission receipt `083589b8-69ad-4ae3-8f78-ef7f1b2e68e7`
proves its stated foundation predicates, not this owner protocol. Stock native
support and live ordinary launch/resume/same-process handoff remain separate.

## Initial source-derived boundaries

[Daemon peer verification](../../src/daemon.zig) and
[native control probing](../../src/integrations/native_probe.zig) currently verify
the user; Linux reads `SO_PEERCRED` but does not propagate its process identity
to the actor. Native listing and mutation use separate connections. These checks
cannot establish a durable process owner. Current actor binding identity contains
application, session and external binding only; metadata and materialization
must gain the same verified owner constraints as acquire. Report duplicate and
restart fallback paths also need verification before returning an acknowledgment
or releasing credit, not only after looking up a process-local lease.

[Request authority](../../src/request_authority.zig) already keys work by exactly
`(application, session_id, request_id)` and permits at most two attempts. An
owner/endpoint/thread/attachment reference belongs to the immutable intent,
not a new work-key namespace. A different owner must mismatch even after the
first attempt was safely rejected. Route identity can distinguish two owners
loading one native thread; this must not manufacture independent replay budgets.

[FileAuthority](../../src/recovery.zig) currently authenticates installation,
sequence and nonce, not complete metadata JSON. Self-consistent persisted owner
rows therefore cannot, by themselves, prove trusted original peer attribution.
The vault/authority reviewers propose a versioned exact snapshot digest and SQL
revision inside the existing independently HMAC-authenticated checkpoint. This
dependency closure is appropriate: a witness-only seal leaves owner phase,
retirement, request and credit constraints mutable. It is a proposed storage
change, not a property of the previous source or proof. The sealed tuple must
bind installation, sequence, nonce, revision and exact bounded stored bytes;
typed outcome validation remains separately necessary.

## Admission and lifecycle conditions under review

Both native control and trusted adapter ingress need socket-derived evidence of
the same supported process incarnation. Claimed PID, shared capability, nonce,
endpoint path or loaded-thread list alone is insufficient. The initial Linux
profile must retain kernel-derived peer identity and explicitly handle reconnect,
PID reuse, socket replacement, namespaces and delegation. Missing proof refuses
before native effects. Darwin and descendant delegation remain unsupported until
their own reviewed profiles pass. A standalone app-server from another process
cannot stand in for a TUI/core process merely because they share configuration.
The real native producer must own the control endpoint in the admitted process.

Core source review identifies two concrete implementation prerequisites. Ordinary
TUI startup uses `InProcessAppServerClient` and
`codex-rs/app-server/src/in_process.rs`, whose processor/router has no native
Unix socket. Updating only the standalone app-server `--listen` path would leave
ordinary startup outside the slice. A shared endpoint must enter both startup
paths in the same process. `Session` construction also invokes
`with_auth_broker_config` before the thread manager publishes the loaded thread;
a startup handshake that requires loaded-thread lookup cannot safely run there.
A prepared provisional core record and final readiness acknowledgment must
resolve that ordering rather than bypass the native producer.

The native reviewers propose an early same-process endpoint with an independent
acceptor holding the shared thread manager/owner registry. Final admission occurs
after `finalize_thread_spawn` publishes the thread and before thread-ready
emission or return. Pending local managed state must block broker streams and
ambient/ancillary authorization from construction onward, including when active
binding lookup is absent. No registry lock may cross an await. The endpoint must
answer while the original start-thread handler is blocked. Native detach needs
an atomic phase/generation transition excluding active broker streams and
ambient/ancillary activity; checking idle before a separate mutation leaves a
race. A lost acknowledgment cannot drop the native thread to ambient authority.

The peer reviewer additionally identified descriptor inheritance/transfer:
`SO_PEERCRED` and `SO_PEERPIDFD` identify the socket's original connection peer,
not necessarily the current writer after descriptor delegation. Merely declaring
delegation unsupported cannot detect this change. The platform profile needs a
concrete enforcement boundary or authenticated per-message evidence; an opaque
pidfd, numeric PID or anonymous-inode `fstat` alone cannot supply it. This remains
a design gate until the source-grounded platform proposal is resolved.

The peer reviewer proposes Linux `SO_PASSCRED`/`SO_PASSPIDFD` and `recvmsg`
credentials/pidfds for every received segment, matched to retained peer pidfd
through a confirmed PID filesystem with stable full-width device/inode identity.
That requires an exact supported kernel/profile gate, namespace and boot witness,
bounded ancillary handling and rejection of truncation, missing evidence,
unexpected descriptor rights or mixed writers before decoding/effects. All
received descriptors must be closed on refused paths. Current libcurl WebSocket
receive consumes ancillary evidence; this proposed owner carrier therefore needs
a reviewed credential-aware transport rather than inheriting the present probe's
proof. No numeric-PID fallback is approved. Durable process evidence binds past
attribution and requires fresh live peer proof after restart; it is not a saved
descriptor or a liveness claim.

Zero-acquire ordinary startup must persist pending registration and its bounded
credit before native managed-mode activation. Late attachment must do likewise.
The real Rust registry needs a pending reservation which prevents replacement or
ambient activity while registration awaits acknowledgment. No registry lock may
be held across RPC; no actor invocation may synchronously await a native callback
which needs the same actor. A precommitted prepared token or bounded actor
continuation can resolve the cycle, but must be checked at the real producer.

Lifecycle proposes bounded off-actor work with typed completions. A dispatch
deadline, caller cancellation, client disconnect or shutdown must never free an
original stack invocation while a worker still references it. Workers need owned
arguments, connection and live peer-handle lifetime; either retain the original
waiter through cancellation/drain or use owned continuation state. Late completion
must match the committed operation and all generation/removal fences before any
update. Shutdown drains owned completions without starting replacement effects.
Completion scheduling must preserve terminal reporting progress under removal
and ordinary request load.

Every acknowledgment must match original operation, owner, process incarnation,
endpoint generation, adapter epoch, thread instance and attachment generation.
Missing, delayed or mismatched acknowledgment retains unresolved custody and
completion credit. Persisted removal admission fences exclude new registration,
attachments, acquire and materialization while allowing the exact original
accepted/unknown work's scoped terminal reports. Partial or unreachable owners
retain configuration and capability; release requires exact acknowledged native
detachment plus request/lease fences. Socket disappearance, process absence,
lease expiry or elapsed time never substitutes for terminal evidence.

Restart must verify the checkpoint/digest before owner restoration can confer
authority and before SQL/native recovery effects. A seal proves a prior trusted
commit, not current liveness, safe detachment, successful external effect or
permission to redispatch. Authority-before-SQL power loss must retain fail-closed
uncertainty rather than silently repair the seal. Legacy unsealed ownerless
bindings remain unresolved; do not sign mutable legacy metadata into verified
peer history, infer yesterday's owner from today's endpoint, delete grants,
reseed keys or reset original work. The migration policy needs explicit user
impact and a bounded compatible conversion or refusal predicate.

The proposed 256-owner and 4,096 attachment/retirement lifetime ceilings count
live, unresolved and retired authority together. Tombstones remain durable; no
TTL evicts them. Whole-snapshot admission must reserve exact encoded bounds,
slots, uncertain completion, final retirement and scalar/ledger growth before
registration or detach. Distinguish irrevocably retained tombstone bytes from
unused effect credit releasable only on a committed acknowledged terminal phase.

## Required meaningful proof boundaries

New acceptance must exercise real private sockets and the real producer, including
two endpoints loading the same thread, wrong ingress/control process pairs,
socket replacement, retained original peer after reconnect, unsupported process
proof and PID-reuse/delegation refusal. Claimed JSON identity is a negative case.
Registration before the first acquire and lost acknowledgment/restart must remain
visible to removal. Race a new registration/acquire against the committed removal
fence; prove original scoped terminal reporting remains possible without new
credential access. Wrong-owner duplicate and restart report paths must refuse.

Crash tests must span pending commit, native effect, acknowledgment and final
commit, retaining original operation and admission credit without repeating work.
Actual 16 MiB and lifetime-record saturation must refuse before native effects,
including retirement growth. Tampered exact metadata, changed revision,
ownerless legacy state and overcommitted migration must refuse before recovery
effects while preserving old custody and fences. A successful model or a new
protocol schema does not replace these actual-path gates.

The existing 1 MiB public frame limit remains distinct from the private 16 MiB
snapshot. Direct actor fixtures do not prove pagination, UI scale or public
transport at capacity. Isolated installed Linux proof does not establish personal
vault/default service activation, Darwin support, provider access or seamless
same-process native continuity.

Review status: initial contract challenges sent directly to authority, vault,
core/protocol and lifecycle owners. No implementation or acceptance approval
has been issued; final source review and root proof receipts remain pending.

## First storage implementation review

R-N13: root released read-only review of actual
[storage](../../src/storage.zig), [recovery](../../src/recovery.zig) and
[new private SQLite fixtures](../../src/native_owner_storage_tests.zig). The new
authority format binds installation, sequence, nonce, SQL revision and exact
snapshot SHA-256 in one 152-byte record, with a distinct HMAC domain and
length-delimited key identity. `finishMutation` measures final transaction-visible
bytes/revision before the independent reserve and SQL commit. Initial '{}' exists
before sequence-zero commitment. Existing authority format and SQL schema2
refuse instead of automatically signing retained attribution. These observations
describe new code under review; they supersede the initial source description
above only for this new epoch, and inherit no previous execution receipt.

One opening-order defect was reported to vault/root: schema3 startup still changes
`journal_mode` to WAL before verifying the supplied wrapping key and exact seal.
Only legacy schema2 receives the new early key check. A retained schema3 database
in DELETE mode can therefore be persistently changed before wrong-key or
substituted-metadata refusal. The requested fix is existing-state key/seal
preflight before journal-mode changes with the final transactional revalidation
retained. The regression must use actual schema3 DELETE mode and prove repeated
wrong-key/bad-seal refusal preserves database and authority bytes. The initial
new refusal fixtures seed WAL mode, so they do not cover this branch. Correction
was requested; the next readback below records its resolution. Root proof remains
pending at this append.

Independent reread of the owner's correction confirms schema3 key, authenticated
tuple and bounded exact-byte seal preflight now precede journal-mode changes.
The same authority descriptor/lock remains held and the checks repeat inside the
exclusive transaction before typed callback or SQL recovery. The new seventh
low-level fixture first converts a genuine schema3 database to DELETE mode,
then exercises wrong-key or valid-JSON substitution. Repeated refusal compares
both database and authority bytes and distinguishes the earlier unsafe ordering.
No remaining concrete blocker was found in this bounded storage/recovery review.
This is source approval only; root-owned compilation and actual test results are
not yet available to this lane.

The remaining reviewed seal code has no additional concrete blocker found:
typed callback/rotation recovery follows exact tuple/digest validation; current
snapshot reads verify their bytes; real child loss after authority reservation
leaves uncommitted SQL and an ahead authority. The new fixture's arbitrary
owner/work/credit JSON tests low-level exact-byte sealing, not actual actor owner
admission or OS attribution. Root must separately prove the real owner restoration
and the peer/protocol/cancellation boundaries described above.

The root-selected transport is a separate bounded 64 KiB `SOCK_SEQPACKET` owner
carrier with per-packet credential/pidfd checks, plus current-writer checks for
every segment on the protected legacy adapter stream. Four full-u64 generations
use canonical decimal strings on the wire; no lossy JavaScript-number coercion
may stand in for exact comparisons. Linux requires the reviewed runtime 64-bit
pidfs/namespace capabilities and refuses missing proof; Darwin remains
unsupported. These are selected implementation conditions, not passing gates.

## First peer bridge implementation review

Read-only review of [C bridge](../../src/platform/native_peer.c), its
[header](../../src/platform/native_peer.h) and [Zig API](../../src/platform/peer.zig)
found no concrete blocker in the bounded capture/receive/descriptor-duplication
paths at this source epoch. Capture retains socket-origin pidfd and compares
user/PID namespaces; receive validates current sender credentials and pidfd
against full process, boot and namespace identity. It checks departure before
and after receive, rejects truncation/unexpected rights/missing or changed writer
evidence, closes delivered descriptors and scrubs received bytes on refusal.
Duplicated actor context owns both socket and pidfd; the original borrowed socket
ownership is preserved. No saved witness-to-live-context conversion is provided.

Caller obligations remain implementation gates: enable evidence before listen or
connect, never concurrently read the same socket through duplicated contexts,
discard and scrub all prior partial frame state on authentication failure, and
carry fresh context through dispatch without accepting claimed JSON process
proof. The receiver's maximum is 64 KiB; the protected legacy stream must validate
every segment used to assemble its independently bounded frame. Actual process
fixtures must create the native listener in the producing process, rather than
inherit a parent-created listener as a purported positive.

The owned process fixture, new carrier integration, real producer and root
executed platform gates remain pending. Structure-only saved-witness tests do
not prove live identity. The primary-source profile review records Linux 6.11+
on 64-bit as the proposed complete namespace/ioctl baseline; actual feature and
permission refusal remain necessary rather than inferring support from version
or headers. Nonprivileged current-writer attribution does not isolate a
compromised kernel/vault or a namespace administrator permitted to spoof peer
credentials. This bounded source approval creates no native support claim.

## Daemon, request and ledger review readback

Root subsequently selected implementation of the complete slice. This releases
actual code review; the initial proposal-only descriptions above retain their
earlier epochs. Current-source support and completed acceptance remain pending.

[Daemon](../../src/daemon.zig) protected adapter framing now captures peer context
before parsing and authenticates every received segment through `nextWithPeer`.
Authentication failure scrubs read-ahead state; frame cleanup scrubs accumulated
partial bytes and closes the connection. Additional buffered frames already came
from validated segments. Actor dispatch owns a duplicated context without
reading that duplicated socket; its uncancelable waiter retains the original
stack invocation until completion. Actor owner/effect checks must independently
recheck live peer authority after queue delay. The new asynchronous native worker
and completion paths still need their own lifetime review when present.

Listener evidence is currently enabled after the standard listen call and before
accept, then enabled again on accepted descriptors. Early queued bytes can lack
required ancillary evidence and safely refuse before parsing or effects. This is
a narrow availability race, not an observed authentication bypass. A custom
pre-listen enable can remove the race; no insecure fallback is justified.

[Request ledger](../../src/request_authority.zig) now rejects immutable NativeRef
mismatch before demand/binding and attempt-budget decisions. Attributed report
checks and mutations repeat exact-reference validation before duplicate or
restart shortcuts; historical ownerless APIs reject attributed records. The four
[request fixtures](../../src/native_owner_request_tests.zig) exercise all five
reference dimensions, safe first rejection without reset, accepted restart
completion, duplicate acknowledgments, ownerless legacy fences and full-u64
reservation restore. This is bounded module source review, not actual actor peer
or two-process isolation proof.

[Owner ledger](../../src/native_owner.zig) preserves zero-owner application removal
fences as lifetime records, rejecting new same-epoch owner/attachment admission
even after fence retirement. Its retained reservation measures actual rows plus
widest future phase, operation and retirement fields separately from effect
credits. Review identified admission of a newer attachment/thread generation while
the same owner's earlier native thread remained nonretired. The owner added
explicit predecessor retirement checks in admission and restoration; no
replacement CAS is authorized. The longest verified-no-effect retirement marker
is included in the conservative future encoding bound. Actor still must prove
exact peer/nonce/operation acknowledgments and request/lease fences before using
these structural transitions to confer or release authority.

Vault's later crash-baseline correction is also source-approved: existing schema3
opening performs a read-only COMMIT instead of writing its unchanged schema
version. The crash child checks a genuine TRUNCATE checkpoint, original metadata
and decryptable retained grant, captures the database baseline, then starts the
crash transaction and reserves independent authority. Parent comparison uses
that pre-reservation baseline and repeats refused-startup database/authority
checks. This preserves the actual power-loss predicate while excluding earlier
authorized opening/checkpoint effects. No new execution receipt is inferred.

Final frozen ledger reread found no additional concrete safety blocker in strict
phase/origin/retirement restoration, immutable generations, prior-retirement
replacement checks or retained future encoding. The eight original model fixtures
cover structural/counting predicates, not live owner authority. Root then approved
a narrow historical-operation refinement: an already-retired owner keeps its
original operation and retirement evidence when a later global removal closes
other live owners. Global readiness/restore may recognize that prior retirement;
they must not rewrite its operation or release old credits again. Actor request
and lease fences remain mandatory. The owner reports a ninth preservation and
delayed-operation regression; its final source and root gate remain separately
tracked by root.

The owned C process fixture now creates/listens in each actual native child. It
keeps origin and delegated writers alive during refusal, distinguishes inherited
and explicitly transferred descriptor writers, exercises mixed stream segments,
rights/truncation descriptor-count cleanup, fresh capture, distinct process
identity, departed retained pidfd and duplicated context lifetime. These are
meaningful bridge predicates in source. No forced numeric PID reuse, namespace
creation or actor/native daemon-restart proof is inferred from them.

## Native owner connection review

[OwnerConnection](../../src/integrations/native_probe.zig) uses protected absolute
endpoint paths, enables credentials before connection, captures kernel peer
context before protocol bytes and retains it across identity and effects. It
uses an absolute bounded deadline and an indivisible 64 KiB packet. Typed parsing
owns every recursively scrubbed key/value, rejects ambiguous envelopes and checks
protocol, original operation, thread, nonce and all four canonical full-u64
generation strings. A partial packet is never resent; exchange or acknowledgment
failure poisons the connection. Legacy WebSocket mutation entrypoints now refuse
before I/O. No concrete blocker was found in this bounded connection review.

This does not complete the vertical authority boundary. The real native endpoint
must pin its incoming register/detach callback sender to the daemon process
witness learned from its outgoing adapter registration, before that request is
sent. Same user and a matching acknowledgment tuple alone do not prove daemon
admission. CLI `announce` can invoke the real native producer; its CLI peer must
never become daemon or native owner authority. Outer actor completion must match
the acknowledgment against its actual persisted inner attached registration,
not merely a preceding identified owner/thread. Clients/core/lifecycle owners
are coordinating these requirements; final actual producer and actor review
remain pending. Existing model/transport source approvals cannot satisfy them.

## Subsequent actor and listener source checkpoint

The current [daemon](../../src/daemon.zig) now uses `listenAdapter`, enabling
writer evidence before bind/listen. This closes the earlier availability race;
unsupported peer profiles still refuse protected requests rather than falling
back to user-only attribution. Protected framing and owned dispatch context
retain the previously reviewed cleanup and lifetime boundaries.

Current [actor](../../src/engine.zig) source places `protectedNativeRef` before
report duplicate acknowledgments and both restart terminal fallbacks, before
ciphertext materialization, and before owner-qualified binding metadata/release.
Acquire requires an open owner and attached generation outside a removal fence.
Original-peer terminal reports remain possible behind that fence through exact
retained request attribution. Route identities include the owner reference;
original request keys remain unchanged. These are current source predicates,
not completed actor acceptance.

The new [native worker supervisor](../../src/native_owner_work.zig) bounds all
queued, running and ready jobs together. Separate announcement and continuation
lanes avoid filling every native worker with announcements that await adapter
callbacks. Completion slots belong to admitted outstanding jobs. The actor
retains the original invocation until completion and drains native work before
closing storage. Final continuation methods, effect-credit attribution and
startup cross-ledger reconciliation remain under active review; this checkpoint
does not approve incomplete integration or infer a passing gate.

The final historical-operation ledger reread accepts the approved refinement:
application removal skips immutable already-retired owner rows, preserving their
original operation. Readiness accepts prior retirement while live owners must
close under the current exact operation. No old credit may be released twice.
Typed restoration mirrors this distinction. The ninth model regression and all
execution receipts remain root-owned.

## Staged Rust implementation review

Read-only review now includes root's isolated development source at
`/srv/fast-local/jess/state/codex/omux-codex-owner-development-20261004/source`.
`owner_control.rs` starts an actual same-process credential-aware endpoint in
both embedded and standalone startup paths. Typed original-frame decoding
rejects duplicate authority fields. Core pending registration blocks managed
streams and ambient authorization; publication precedes final registration and
thread readiness follows its committed reply. The outgoing adapter request pins
the daemon's actual witness before sending bytes. Native activation and exact
detach, including a retired duplicate receipt, compare the callback peer to that
pin. Core request/native-work/ambient counters share the registry transition
lock, keeping active work from racing the final detach mutation. These are source
observations, not installed-process or live continuity proof.

One concrete callback ordering blocker was sent to protocol/root:
`ThreadRequestProcessor::owner_activate` currently calls `owner_attach_admission`
before `activate_registration` authenticates the pinned daemon peer and complete
pending tuple. The admission helper shuts down cost delivery, disables analytics,
enters broker-local mode and drains MCP authority. A wrong callback with matching
configured paths can therefore cause native effects before refusing. The minimal
fix verifies pending tuple and pinned peer without mutation before that helper,
then repeats the existing atomic activation checks after asynchronous drain.
The discriminating gate must prove a wrong peer/nonce/generation/operation never
reaches the drain boundary. Final corrected source and root proof remain pending.

Cross-method operation linkage also remains an integration checkpoint: late
`owner_announce` currently carries its supplied operation into the inner
`adapter.owner.register`. If the actor admits `integrations.attach` under that
same global mutation ID, the distinct method conflicts. Lifecycle/protocol owners
must use stable retained linkage rather than silently generate another attempt
or change the original model-work key. No incomplete-method source is treated as
a passing path.

The current producer pins the original daemon process witness for every later
broker RPC. A daemon process replacement is refused; surviving-native-process
reconnection to a replacement daemon is not implemented by this pin. Synthetic
actor restart terminal-report gates cannot prove that producer behavior. The
current endpoint service also installs one process owner: a second embedded
processor endpoint in that process refuses replacement. Both limitations must
remain explicit in the selected installed checkpoint and future claims.

Subsequent source reread confirms the native callback ordering fix is wired:
`owner_activate` calls nonmutating `check_registration` before ancillary drain;
`activate_registration` repeats the same locked full predicate afterward. The
original wrong-peer-before-effect source blocker is closed. Root ratified a
deterministic domain-separated internal registration mutation ID; attachment,
credit and acknowledgment keep the producer's original operation. Begin/replay
now use the internal mapping. Startup must recompute its retained association;
no proof or complete restoration approval is inferred from this interim read.

Two concrete actor task-lifetime conditions were sent to lifecycle while the
continuation implementation was landing. `NativeContinuationPending` after a
successful requeue must retain the task and original invocation, rather than
enter generic failure cleanup and free a queued worker pointer. Task-array
capacity must also be reserved before enqueuing initial removal work, so an
allocation failure cannot free a queued task. Failed committed restoration or
uncertain-disposition persistence must poison the actor; current
`failNativeTask` now contains that error fence. Final continuation source and
coordinated gates remain pending.

Current source closes the removal continuation ownership conditions: the
continuation sentinel returns without finishing/freeing the task, and initial
removal reserves task-array capacity before enqueuing. The shared fixture now
clears joined worker handles before a replacement spawn and scrubs its received
capability-bearing packet buffers. Registration results now have the exact
`registered`, `operation_id`, `native_ref` variant accepted by the real producer;
detach uses its distinct `detached` variant. The earlier extra-field wire blocker
is closed in source, with actual producer decoding proof still root-owned.

Startup validation now restores the structural native ledger before the storage
callback permits recovery, reconciles domain bindings/leases and immutable
request references against retained owner/thread rows, refuses ownerless Codex
attribution, recomputes internal registration IDs and removal child operations,
checks reciprocal native phase/credit obligations, and applies the same-candidate
native reservation to the full private envelope. This does not construct live
peer context or resume an uncertain effect from JSON. Final current-input gates
remain necessary.

One interim install/removal race report was withdrawn after reading the latest
shared setup guard: `setupOptions` derives a typed removal permit from the global
application fence, and `setup.install` requires `install_ready`. Replacement is
already refused behind that fence. Setup also compares the retained registry
transaction and capability digest at its locked write boundary; refreshing
mutable startup configuration alone never proves native ownership.

The primary read-only discovery extension keeps capabilities and thread rows on
one captured owner connection, validates exact protocol/typed fields and
canonical full-u64 generations, bounds packets and rows, owns returned strings,
and compares owner, nonce, endpoint generation and witness across responses.
Listed/reserved attachment generations and saved witnesses remain metadata,
never admissions. Legacy WebSocket mutation APIs still refuse before I/O.
No additional concrete blocker was found in this bounded extension review;
malformed-response gates and installed native discovery proof remain separate.

Latest shared `ActorFixture` review finds owned callback shutdown ordering:
pause clears the raw producer callback pointer, stops acceptance and joins all
native workers while the old engine remains alive. Restart/destruction free the
engine afterward; resume does not recreate peer context from saved metadata.
Actual fixture install uses the control mutation and V2 read-only negotiation,
and checks that discovery did not call register/announce. The producer and actor
still share one test process. The removal continuation now retains the admitted
registry witness and rechecks it before setup removal, in addition to the shared
locked transaction/digest check. No additional blocker was found in this source
checkpoint; current-input acceptance and installed artifact closure remain
root-owned.

Latest staged producer reread closes the late-announcement admission window:
`owner_announce` checks inputs and loaded-thread metadata, then atomically creates
the pending registration reservation before awaiting the daemon. Pending native
authorization is blocked throughout that wait. Ancillary drain occurs only in
the authenticated activation callback after daemon admission. Core's actual-task
fixtures are prepared to exercise pending refusal and a live unmanaged task;
their execution remains a separate root gate.

The structural owner key now includes raw owner ID, adapter epoch and endpoint
generation. A replacement incarnation requires every older same-ID owner to be
retired; the old witness, references and receipts remain immutable. Engine
admission, attribution, terminal reporting and removal now use qualified owner
lookups. Startup also checks both directions of the original internal
registration-record association and the exact cached operation/ref/result
variant, alongside reciprocal pending credit obligations. No additional
attribution or replay bypass was found in this bounded source checkpoint.
The attachment-generation allocator still needed the same incarnation scope at
this readback: scanning retired rows from another epoch/endpoint can cause an
unnecessary overflow refusal for a new incarnation. This is a routine availability
correction reported to lifecycle, not an ownership bypass.

The following readback confirms that allocator correction: the scan now requires
the current adapter epoch and identified endpoint generation as well as owner ID
and thread instance. The reported overflow-refusal seam is closed in source.

These observations do not establish stock-application support, native producer
continuity across daemon-process replacement, automatic endpoint advertisement,
or live account handoff. Those remain exact-artifact and installed-path gates;
the original model-work namespace and accepted-stream replay prohibition remain
unchanged.

The reopened frozen-source review includes `engine_acceptance.zig`,
`snapshot_native_tests.zig`, `snapshot_repair_tests.zig` and
`native_owner_work.zig`. The acceptance harness obtains references through actual
registration, scopes them by actor state directory/session or acquired handle,
uses verified packet transport, joins producer workers before actor destruction,
and never silently registers an owner during reopen. The migrated native cases
exercise real V2 install, oversized packet/thread refusal, saturation before
native/configuration effects and removal from the retained original registry.
The repair case retains its exact snapshot/ciphertext/authority comparisons and
reachable submission-tripwire positive control. These are synthetic Zig
producers in the test process, not the patched Rust application or a separate
daemon-process restart. No concrete blocker was found in these bounded source
paths; coordinated execution remains root-owned.

Core identified a separate ordinary-launch availability defect: unconfigured
`Session::new` propagates owner metadata capacity/generation exhaustion before
checking configured managed custody. The agreed correction preserves ordinary
ambient construction only for unconfigured sessions, keeps configured
registration fail closed, and makes read-only thread enumeration refuse the
entire unsupported result rather than omit untracked loaded threads. That
correction was planned, not present, at this checkpoint and requires its own
source readback and actual-path gate.

Subsequent readback confirms that core correction: configured registration still
requires identity admission; unconfigured construction explicitly accepts
`Prepared` or `Unavailable`. Capacity/exhaustion leaves metadata unchanged,
unprepared identify/listing refuses, and poisoned registry errors propagate.
The ordinary-launch source defect is closed; this is not an executed producer
receipt.

During the first full gate failure review, the installed custody fixture exposed
a concrete independent SQLite connection lifetime error:
`with sqlite3.connect(database) as metadata` commits or rolls back, but does not
close the connection. Its first inspection connection remains referenced across
daemon restart and competes with the production exclusive writer. The narrow
fixture fix explicitly closes inspection connections before restart or database
replacement; writer locking and checkpoint admission must remain unchanged.

The request fixture's long temporary state path reaches `setupOptions` before
native work is enqueued, explaining its possible registration refusal under the
unchanged 107-byte socket limit. The reviewed actor completes the original
Invocation under its mutex, dispatch waits uncancelably, continuation ownership
is retained and native workers join before actor storage is freed. No escaped
stack/task reference was identified in that bounded source review. The separate
case-six segmentation fault has no source attribution from its reported address;
the short-root/defer correction alone must not be described as proving it fixed.
A fresh focused root gate remains required.

Corrected fixture source now explicitly closes both installed SQLite inspection
connections. The request Actor uses an exclusive short 0700 root, a retained
alias-checked descriptor, a separately owned sentinel path and exact device/inode
comparison before deleting its generated tree. Restart clears its engine pointer
before teardown. Neither correction weakens production socket bounds or creates
native authority. No additional concrete blocker was found in this readback;
the reported abort remains an execution question until the focused gate returns.

Final typed-refusal source review found no concrete blocker in the new slice.
Core recognizes the private `NativeOwnerPending` error payload by downcast,
rather than matching message text or suppressing all `WouldBlock` errors.
Registry poison, capacity and other native errors retain the `Other` fault path.
Submission handlers refuse before dispatch effects; task spawn/start refuse
before aborting or replacing tasks and before entering task execution. The
app-server bespoke handler emits an explicit nonretrying pending notification
and skips native system-fault accounting and accepted-turn summary mutation only
for this typed refusal. Other errors retain ordinary fault handling.

The reviewed protocol and guards still check the complete pinned daemon peer and
original owner/nonce/operation/generation tuple before ancillary drain, repeat
the locked activation predicate after asynchronous work, reserve late-announce
pending state before the daemon wait, and require the original peer plus exact
reference and drained activity at the detach transition. None of these changes
creates a new original-work namespace, permits an accepted-stream replay or
restores a live peer context from saved metadata.

Root reported the current Omux eight-target slice passing, including the
previously aborting request case, and the Rust core/app-server/protocol predicate
slice passing. Those are root-owned receipts for their stated inputs, not this
reviewer's execution. Packaging, installed patched-Rust/daemon interoperability,
ordinary native resume and live same-process account handoff remain separate
gates. Stock application support, producer continuity across daemon-process
replacement and automatic endpoint advertisement are not promoted by this
source review. This note is frozen at the final typed-refusal checkpoint.
