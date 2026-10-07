# Native owner lifecycle review — 2026-10-04

R-N13 authorizes this review note only. Runtime implementation awaits root's
plan/type release. Baseline is checkpoint `c73368fb` under the private
`omux-native-admission-frozen-20261004` custody root. No build, test, generator,
host, provider or tracker action was performed in this lane.

The [native reset](../plans/omux-native-account-lifecycle-reset-2026-10-02.md)
remains active. The [owner proposal](../plans/omux-native-owner-custody-next-stage-2026-10-04.md)
is the reviewed next-stage input, not existing support. This note proposes the
smallest complete Linux owner slice. Stock Codex, Darwin owner attribution,
delegated processes and live continuity remain unproved; PZM remains held.

## Reachable current paths

`Engine.actor` runs `execute` synchronously. `publicIntegration` calls loaded
thread discovery and then register/unregister directly; `detachForRemoval`
does the same before `setup.remove`. Those calls occupy the lifecycle writer.
Introducing a native handler that synchronously calls the adapter channel from
inside registration would deadlock: that callback queues work to the occupied
actor. Existing dispatch retains each caller's stack `Invocation` until the
actor signals completion; this lifetime guarantee must survive continuations.

`daemon.verifyPeer` and native-probe verification enforce peer UID, but discard
Linux process credentials. Daemon dispatch receives channel and JSON, without
verified process context. Discovery, registration and unregister open separate
native connections. Paths, shared capability and thread ID therefore cannot
establish a durable same-incarnation owner today.

Bindings use `bindingIdentity(application, session, external_binding)`. Acquire
retains `(application, session, request_id)` in request authority and prepays a
terminal report credit. Metadata, materialization and release lack an owner
dimension. `report` checks cached acknowledgment before `nativeLease`, and its
unknown/accepted restart terminal fallbacks use application and handle alone.
Every one of these paths needs the new owner gate; changing acquire alone leaves
reachable shared-capability authority bypasses.

`requireObservedCodexBindings` prevents one endpoint's incomplete loaded list
from releasing recorded distinct-thread routes. It cannot distinguish two
processes resuming the same thread, or remember attachment before first acquire.
Uninstall has no persisted admission fence excluding a concurrent registration.
Setup recovery and install's completion of pending removal must also consult
such a fence, not just the explicit uninstall path.

## Shared input and authority contract

Coordinate one `NativeRef` definition in the new authority module: internal
`owner_id: [32]u8`, plus nonzero `u64` adapter epoch, endpoint generation,
thread-instance generation and attachment generation. The wire owner ID is
opaque 64-character hex. The owner record additionally retains application,
process nonce, private endpoint witness, native thread ID, original registration
or removal operation, phase and its exact outcome plan/credit. Default JSON
serialization of internal byte arrays must be counted as arrays, not assumed
to have the hex wire size.

Protocol review also requires a lossless JSON/TypeScript generation encoding:
proposed canonical nonzero decimal strings on the wire, parsed into internal
`u64`, avoid JavaScript's precision loss above `2^53-1`. Root must ratify exact
field names and schema encoding before candidate/runtime edits.

`PeerContext` comes from the accepted socket, through a private dispatch API;
JSON PID fields never create it. Compare actual ingress and control peer
incarnation evidence, native nonce and endpoint generation. Hold the verified
connection through observation/mutation, or prove the same incarnation on every
replacement connection. A process-local FD is not a serialized witness. OS peer
review must settle socket inheritance/transfer and delegation: a connection's
origin credentials alone must not be described as proof of every later writer.

Binding identity adds owner, thread-instance and attachment authority. Binding,
lease and immutable request intent carry the same `NativeRef`. The request key
stays exactly `(application, native session, original request_id)`; owner fields
are constraints, never another work namespace. A mismatched owner cannot claim
the alternate attempt after safe rejection. Registration operations have their
own stable IDs and cannot replace a model UUID or reset the two-attempt budget.

Validate verified peer and exact retained ref before acquire, metadata,
materialization, cached report acknowledgment, every restart fallback and
release. An integration removal fence blocks new owners, attachments and leases
but preserves the original owner's scoped terminal-report authority. A deadline,
zero current in-flight count, missing process or disappeared socket is not
terminal evidence for unknown/accepted work.

## Actor continuation sequence

1. The actor verifies incoming peer context and negotiated native v2 identity,
   snapshots owned bounded arguments, preflights the final cached result and
   reserves byte/slot outcomes. It commits pending registration or pending
   detach with original operation, typed witness and credit before native effect.
2. A bounded native worker owns the connection, arguments and deadline. It does
   native I/O outside the actor and returns an owned typed completion. It cannot
   mutate domain, request authority, SQLite or another operation's credit.
3. The actor compares owner, process nonce, endpoint/adapter/thread/attachment
   generations and original operation against the committed witness. It commits
   attached or detached outcome before completing the mutation/reply and
   releasing only that owner's remaining credit. Mismatch or lost acknowledgment
   retains unresolved custody and credit; no blanket binding release follows.
4. Invocation remains owned until completion or a committed uncertain result.
   The current synchronous `authorizedRequest` needs an explicit deferred result,
   not a suspended borrow of parsed JSON or `active_credit`. Each continuation
   installs its original active-credit key only for its own actor transaction.
   Bounded completion capacity is admitted before effects and cannot be starved
   by control queue backlog. Shutdown stops new effects, drains or fences native
   work, joins its owners and finishes every queued/deferred stack reference
   before actor storage closes.

Ordinary startup and late attach use this same sequence. Producer review found
ordinary embedded TUI has an in-process app-server router but no native Unix
listener; using a separate app-server process would fail same-incarnation proof.
The candidate therefore needs a private lifecycle endpoint in the actual native
process. Current core registration occurs before ThreadManager publication.
Prepare startup state early, then register after publication and before exposing
the thread or admitting its first model request. Keep native activation free of
a synchronous actor dependency while native registration is outstanding. The
startup producer waits for the daemon's committed registration result before
the first acquire. Preserve ancillary drain, exclusive renewal ownership and
native context checks; generation equality cannot replace those predicates.
The startup handler must also avoid waiting behind its own globally thread-ID
keyed start/resume queue while that queue awaits registration.

## Removal, source lifecycle and migration

Persist one epoch-bound removal fence and bounded complete owner list before
detach. Include never-acquired attachments. Each exact acknowledged generation
retires only its own route/attachment. Partial, busy, unknown, replaced or
unreachable owners retain the fence, configuration, shared capability and
credits. Config restoration and capability epoch retirement occur only after
all required native ACKs and original request/lease fences permit them. A new
explicit attachment generation cannot revive a retired generation.

Account-source epochs and forget tombstones remain separate from native owner
authority. Source disconnect invalidates that source's grants and deletes its
ciphertext; it does not prove native detach or terminate accepted work. Account
forget currently refuses retained leases. It may remove an idle binding, but
must not erase the independent native attachment ledger. Preserve independently
valid grants and external renewal ownership throughout owner operations.

Migration requires a new explicitly validated snapshot version before custody
or setup effects. Preserve original request keys, both attempts, mutation IDs,
ciphertext, account tombstones and owner retirement history. Missing legacy
owner refs are unresolved, not today's endpoint attribution. Do not silently
drop or rekey them. Unknown or overcommitted obligations refuse conversion.

Private structural metadata and authenticated checkpoint lineage do not MAC the
whole snapshot today. Vault review proposes a versioned final-snapshot digest
and revision commitment in FileAuthority; root must settle that storage design
before retained owner witnesses can confer recovery authority. Startup retains
phases, original witnesses and credits but marks live verification unavailable.
It cannot redispatch registration, detach or a model call from retained phase.
Any surviving-owner terminal report needs fresh peer attribution to its original
sealed ref; missing proof preserves the obligation. Native process-restart model
continuation and automatic exit retirement stay deferred.

## Concrete implementation inputs and gates

The coordinated file boundary is: new owner authority/types module; peer bridge
and `daemon.zig` dispatch context; `native_probe.zig` retained verified native
connection and typed v2 ACK; `engine.zig` deferred invocation/native work,
owner gates and removal sequence; `domain.zig` binding/lease refs;
`request_authority.zig` immutable intent constraints; `snapshot_admission.zig`
owner/attachment slots and outcome bounds; `storage.zig`/`recovery.zig` explicit
trusted migration; `setup.zig` removal permit. Rust protocol, core broker,
embedded/main process endpoint and post-publication producer changes belong to
a new exact candidate epoch with declared schema generation. Proposed lifetime
limits of 256 owners and 4,096 attachment/retirement records require root
ratification and production-envelope sizing; no TTL eviction.

Actual gates must cover two private processes loading the same thread ID;
registration before first acquire; reentrant callback without actor deadlock;
wrong peer/nonce/epoch/generation/operation ACK; removal racing registration and
acquire; partial detach with config/capability retained; original-owner terminal
report behind the fence; crash before/after effect, ACK and commit without repeat;
unknown/accepted and rejected-first work across owner replacement/migration;
real byte/slot saturation before effects; and ownerless/invalid migration
preserving original metadata and ciphertext. These are required future
predicates, not passing receipts. Root owns locked Nix/Bazel execution and the
separate exact installed Linux artifact proof.

## Source checkpoint, 09:45:12Z

The actor integration and new bounded `native_owner_work.zig` supervisor are
frozen for root-owned compilation, without an execution receipt from this lane.
Native registration identifies the retained verified endpoint, commits the
pending attachment, original operation and outcome reservation, then activates
outside the actor and commits its exact ACK before reply. Late attach first
identifies and prepays both outer and inner authority; only the genuine native
producer callback matching the live original announce can activate it. The
internal registration mutation ID is the SHA-256 hexadecimal digest of the
fixed `omux.native.mutation.v1.adapter.owner.register` domain and original
64-byte producer operation. The attachment, credit and wire operation remain
unchanged. Model request keys and their two-attempt budget remain unchanged.

The eight-task supervisor has separate announcement and continuation lanes,
reserved producer callback slots and actor-prioritized bounded completions.
Owned waiters, protocol arguments, peer duplicates and native connections remain
alive through cancellation, timeout and shutdown. V2 discovery runs outside the
actor and its prospective attachment generation is diagnostic metadata.

Owner lookup is qualified by immutable `(owner_id, adapter_epoch,
endpoint_generation)`. A new incarnation requires every preceding same-ID
incarnation retired; old rows, refs and request acknowledgements remain intact.
Removal commits an application-wide fence before any detach, including with no
owners. Accepted/unknown/issued requests retain their capability and exact
terminal-report authority. A detach uses original sealed attribution and a
deterministic child operation, commits only an exact peer/ref/nonce/operation
ACK, and retains partial/uncertain custody. Final setup removal checks the
retained installation transaction and capability witness; startup never
redispatches pending native effects or adopts missing live work.

Startup validates qualified binding, lease, request and native-credit links,
original registration-record mapping and exact cached result/ref correspondence.
Storage's independent full snapshot seal supplies original persistence evidence;
neither metadata nor the checkpoint claims current process liveness. The native
ledger's permanent phase/retirement reservation is included in the whole 16 MiB
JSON budget and excluded from unrelated effect debits. The registration result
has exactly the producer's three fields and lossless decimal generation strings.

Uncertain registration retirement remains held: structural verified-no-effect
support does not constitute a runtime reconciliation or status producer path.
Old ownerless synthetic adapter fixtures require genuine peer/helper adoption;
there is no acceptance bypass. These source facts do not establish passing actor,
same-process protocol, ordinary launch or installed artifact proof.
