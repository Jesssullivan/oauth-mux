# Codex native owner protocol and transport review

R-N13 records this review and this note's documentation mutation for the
user-selected native-owner/Codex-protocol sprint. Only this note was changed.
The prepared candidate remains untouched; root owns the new source epoch and
all locked Nix/Bazel execution. R-N11 preserves other sessions and dirty work;
an actual guard refusal requires the R-N12 stop. No build, test, script, host,
provider, service, upstream or tracker action was performed. PZM remains held.

The [native reset](../plans/omux-native-account-lifecycle-reset-2026-10-02.md)
is active. The [owner proposal](../plans/omux-native-owner-custody-next-stage-2026-10-04.md)
is unimplemented and unratified. This review supplies implementation choices
and missing predicates, without promoting native support or live continuity.

## Actual candidate boundaries

Inspected source is the immutable prepared candidate at
`/srv/fast-local/jess/state/codex/omux-codex-source-00c972ed/source`, pinned by
[manifest.json](../../integrations/codex-upstream/manifest.json) to official
Codex commit `00c972ed5d6ff6499317fd41b7f23605b8e6850d`, tag
`rust-v0.157.0`. The paths and line references below are within that source.

| Actual source | Finding |
| --- | --- |
| `codex-rs/app-server-protocol/src/protocol/v2/thread.rs:1689` | Hook version 1 registration carries thread, binding, broker socket, capability path and version. Its response acknowledges binding and refresh ownership. Unregister carries thread and optional release flag and returns only a boolean. None carries exact owner, native process nonce, endpoint/thread/attachment generation or stable operation acknowledgment. |
| `codex-rs/app-server-protocol/src/protocol/common.rs:846` | Capabilities, register, unregister and status methods are registered. Register/unregister serialize by native thread ID. The app-server API's `v2` namespace is separate from the broker hook's current version 1. |
| `codex-rs/app-server/src/request_processors/thread_processor.rs:956` | Register requires a loaded supported idle thread, no running agent and stopped realtime; drains native telemetry, local-only ancillary authorization and MCP authority before core registration. Unregister inspects idle thread history and refuses account-bound context. These checks must survive owner changes. |
| `codex-rs/app-server/src/message_processor.rs:1505` | Broker handlers receive payloads without verified connection context. Register also stops the turn-cost worker. Existing connection/request IDs do not establish native process authority. |
| `codex-rs/app-server-transport/src/transport/unix_socket.rs:203` | Accepted Unix streams enter the generic WebSocket runner. `websocket.rs:187` emits `ConnectionOrigin::WebSocket`, `auth: None`; local peer attribution is lost. Private directories and mode 0600 establish path protection, not exact process ownership. |
| `codex-rs/app-server-transport/src/transport/mod.rs:183`, `codex-rs/app-server/src/transport.rs`, `message_processor.rs:174` | Transport events, connection state and session state retain origin and RPC authorization, but have no immutable verified native peer witness. JSON initialization names/version are client assertions. |
| `codex-rs/uds/src/lib.rs:56` | The wrapper exposes asynchronous read/write and connection operations, without a Unix peer-credential accessor or credential-aware receive path. Adding an accepted-peer field alone would not authenticate subsequent writers of a delegated connected FD. |
| `codex-rs/app-server/src/in_process.rs:427` | Ordinary embedded TUI startup builds an in-memory processor/router and an InProcess session, without a Unix acceptor. `app-server/src/lib.rs:786` creates that acceptor only for UnixSocket transport. A separate app-server process cannot prove ownership of the embedded native process. |
| `codex-rs/core/src/thread_manager.rs:2342` | `finalize_thread_spawn` publishes the constructed thread in its map after SessionConfigured. Core review found current configuration-driven registration inside Session construction, before this publication. A daemon callback to the loaded-thread handler at that point cannot succeed. |

The in-process loop awaits `process_client_request`, but initialized dispatch
enqueues bounded work or spawns an unscoped task (`message_processor.rs:968`).
This is not evidence that every request blocks that loop until completion.
The concrete risks are pre-publication lookup and waiting on a callback behind
one's own thread serialization or held locks. `request_serialization.rs:25`
keys thread queues globally by thread ID, not by connection. Existing
register/unregister scope must not become an uncontrolled concurrency bypass.

## Coordinated complete producer

Core and lifecycle reviewers agree on an early private owner endpoint in the
same process, plus registration after thread publication and before exposure
or first request. Both embedded `in_process.rs` and ordinary app-server startup
must initialize that process-owned endpoint. It must never resolve to another
process's shared daemon endpoint. Generate one process-lifetime random nonce,
one bounded endpoint generation and one registry shared with core. Reading
broker configuration alone neither activates nor enrolls an owner.

Use the concrete publication boundary in `finalize_thread_spawn`: insert the
thread without retaining the map lock, then complete owner preparation and
registration before ready/resume lifecycle publication and returning NewThread.
Core must fence turn/provider/ancillary admission while that thread is pending.
Failure cannot silently fall back to native refresh after partial activation.
Resumption requires a fresh thread-instance generation. This placement is a
proposal: ordering with SessionConfigured events and all other consumers of
the thread map requires actual-path tests before acceptance.

An independently scheduled bounded native handler holds the shared owner
registry and exact ThreadManager/readiness references. The daemon commits
pending custody and growth obligations before dispatching native work off its
actor. Native activation validates and changes the prepared local registration,
then acknowledges on the established control channel without a synchronous
daemon callback. The daemon commits the matching attachment before replying
to the waiting producer. No actor, thread-map, registry or serialization lock
may be held across that round trip. Startup and late attachment share the
same exact activation rules; late attachment retains all loaded-idle,
telemetry, MCP, realtime, context and refresh-owner checks above.

Do not implement a broad second app-server surface merely to obtain a listener.
A dedicated bounded owner carrier can reuse typed broker payloads and shared
native handler logic while exposing only identity/prepare/activate/detach/status
operations. Alternatively the existing Unix WebSocket carrier needs a reviewed
credential-aware underlying stream and independent startup dispatch. Root must
choose the complete carrier with the peer reviewer before code mutation.

## Proposed wire contract and acknowledgments

Authority/lifecycle own the shared native reference: opaque `ownerId` (64 hex
characters), nonzero internal u64 `adapterEpoch`, `endpointGeneration`,
`threadInstanceGeneration`, and `attachmentGeneration`. The owner record also
binds a native `processNonce` (64 hex characters), exact native `threadId`,
verified private endpoint witness and stable original `operationId`.
Wire assertions supply lookup constraints; they do not manufacture peer proof.

Capabilities must negotiate a new broker-hook version and explicitly attest
the complete owner/peer/attachment contract. A v1 peer cannot satisfy it by
returning the existing seven booleans. Process identity discovery must be
available before thread activation; its nonce and endpoint generation belong
to the independently verified process, not to caller-supplied capability params.
Required fields must not default or be optional on attach/detach. Unknown
authority-bearing fields and unsupported hook versions refuse.

Register and unregister acknowledgments must echo the original operation,
owner, process nonce, adapter epoch, endpoint generation, exact native thread,
thread-instance generation and attachment generation. Detach adds a typed safe
terminal result after native context inspection and local registry removal.
The existing `unregistered: true` cannot retire arbitrary custody. Native
retries of the same operation return the same committed outcome; a different
tuple cannot reuse its receipt. Lost replies retain daemon unresolved custody.
Thread status reports bounded exact-generation state without credential reads.

Keep camelCase serde and TS names, plain string handles and `v2/` exports in
the app-server protocol. Existing capability keys have a targeted snake_case
compatibility shape; any new shape must be explicit and versioned. Full-range
u64 generation encoding remains a shared contract decision: canonical decimal
strings with a strict nonzero parser avoid JSON/JavaScript number rounding.
A TS-only string annotation would not change Rust JSON serialization. Schema
and runtime tests must exercise boundary/overflow cases with the chosen format.

Core must include this reference in immutable adapter intent, route, metadata,
materialization, release and every report/duplicate/restart path. Security
requires wrong-owner opaque-handle and duplicate-report refusal. The original
work key remains application/native session/original request ID; adding owner
identity must not create another two-attempt budget or permit accepted replay.

## Transport and platform dependencies

Peer review requires bidirectional Linux socket-origin and per-read writer
evidence. `SO_PEERCRED`/`SO_PEERPIDFD` describe the original connection peer,
not every later writer after FD delegation. A reviewed receive carrier must
enable the selected credential/pidfd options before accepting or connecting,
inspect bounded `recvmsg` ancillary data for every received segment before
frame assembly, and reject truncation, missing/changed writer identity,
unexpected rights and unsupported kernel/profile behavior. Hold and compare
the reviewed pidfs witness; numeric PID lookup is not the authority. These are
the OS reviewer's proposed requirements, not implemented support.

Immutable verified context must flow from accepted socket/receive validation
through TransportEvent, ConnectionState/Session and broker dispatch. Ordinary
TCP WebSocket, remote-control, stdio or in-process client assertions must not
inherit owner admission. Internal calls need separately typed prepared authority.
The owner endpoint's independent task still requires the same bounded frame,
deadline, connection and task admission as the existing server. Existing pinned
Tokio/libc dependencies occur in `uds` and `app-server-transport`; using them
does not establish that the required kernel API/constants are covered. Root
owns dependency declarations and the kernel/toolchain profile gate. Darwin
UID-only attribution remains unsupported for this owner profile.

## Root-owned schema and proof gates

Declared candidate labels identified by BUILD files and `defs.bzl` are:

- `//codex-rs/app-server-protocol:app-server-protocol-unit-tests`, including
  actual JSON/TS fixture matching and stable/experimental precomputed exports.
- `//bazel/schema:public-schema-bundle`, whose declared actions use
  `//codex-rs/app-server-protocol:schema-generator` to produce stable and
  experimental schema trees; this build alone does not replace source fixtures.
- `//codex-rs/app-server:app-server-unit-tests` and
  `//codex-rs/app-server:app-server-all-test` for shared handlers/public RPC.
- `//codex-rs/app-server-transport:app-server-transport-unit-tests` and
  `//codex-rs/uds:uds-unit-tests` for actual private carrier behavior.
- Core/TUI/CLI compilation and `//codex-rs/core:core-unit-tests` are producer
  dependencies, coordinated with the core reviewer and root.

Root must regenerate and normalize all changed JSON/TS and compressed
precomputed exports from the declared schema actions, update the isolated
candidate manifest/patch custody, then run the relevant locked Bazel gates.
Existing candidate receipts cannot certify changed protocol bytes.

Required meaningful tests cross actual boundaries: ordinary embedded startup
exposes the same-process endpoint before activation; first acquire waits for
persisted attached state; daemon callback completes while thread startup is
held; two private processes loading the same thread attach and route separately;
wrong peer/ref/handle/operation/generation refuses without effects; replacement
endpoint and delegated-FD frame segments refuse; partial/truncated/missing
ancillary data refuse; native idle/realtime/MCP/telemetry/context checks remain;
duplicate attach/detach ACKs match exactly; lost ACK and restart retain custody;
and no accepted work replay or renewed attempt budget occurs. Prove these
through real RPC/carrier/core paths with generated private metadata and no
provider access. Static schema round trips alone cannot prove them.

No proposed gate was run in this review. Ordinary launch, native resume,
same-process handoff and preserved session/history/tools/approvals still require
separate exact-version live evidence after the implementation gates pass.

## R-N13 implementation preparation after carrier ratification

The active [owner sprint](../plans/omux-native-owner-sprint-2026-10-04.md),
starting `08:28:06Z`, now ratifies a Linux SOCK_SEQPACKET owner endpoint with
64 KiB packets, canonical decimal generation strings and the reviewed current
writer profile. This supersedes the unresolved carrier choices above for this
new implementation epoch. Root is preparing and verifying a separate candidate
development root; the inspected original remains immutable. No candidate edit
is authorized before that release.

Root assigned this worker the new app-server endpoint/protocol/startup files
and `core/src/native_peer.rs`, exact copies of the reviewed Omux
`src/platform/native_peer.c` and `.h`, and the core `lib.rs` module export.
Root owns the candidate core BUILD change linking the C bridge. The core
worker remains sole writer of auth_broker, Session, ThreadManager and client.
The C copies must retain identical bytes until a coordinated reviewed bridge
change; this avoids two independent ancillary parsers. Rust owns descriptors
through RAII, bounds intrinsic syscall deadlines to at most 15 seconds and
exposes verified stream segments and packet operations. Core's existing raw
BufReader exchange must use that stream API on bounded blocking work; the
daemon/app-server actor must not perform blocking socket reads.

The frozen owner JSON-RPC 2.0 carrier uses `owner/identify`, `owner/register`,
`owner/unregister` and `owner/announce`, with exact request IDs and integer
`protocolVersion: 2`. Identify is read-only: params contain protocolVersion
and threadId; result contains protocolVersion, ownerId, processNonce,
endpointGeneration, threadInstanceGeneration and threadId. Native process
startup generates stable ownerId and processNonce; the daemon alone assigns
adapterEpoch and attachmentGeneration after bidirectional OS verification.
Register/unregister requests and ACKs carry the complete previously described
tuple. Register requests additionally require brokerSocket and capabilityPath
so an already running unconfigured native process can attach through reviewed
private-path checks. Responses add registered:true or unregistered:true;
unregister must not synchronously call back to release daemon authority.

Announce params contain protocolVersion, threadId, operationId, brokerSocket
and capabilityPath. A concurrent endpoint worker prepares the native tuple,
then makes the actual authenticated native `adapter.owner.register` call.
The native producer's snake_case payload contains application, capability,
owner_id, process_nonce, owner_endpoint, thread_id, endpoint_generation,
thread_instance_generation and operation_id. CLI peer identity never becomes
native owner authority. Announce returns the complete registered tuple only
after the daemon's committed acknowledgment reaches the producer. Other
connections remain able to receive the daemon's native activation callback
while announce awaits that reply. Both channels validate their actual writers.

Coordinated core APIs prepare a pending registration, identify its native
tuple, activate the exact daemon-assigned tuple locally without a callback,
and finish registration only after the original daemon RPC returns the same
tuple. Local activation alone leaves all work blocked. Lost or mismatched
results retain unresolved pending state. The private endpoint starts in both
main and embedded app-server paths before any session/client work. Ordinary
registration occurs after real ThreadManager publication and before native
readiness; late announce preserves the loaded-idle, ancillary and context
checks. Endpoint activation uses the independent shared handler rather than
being queued behind the originating startup/announcement request.

Preparation still has no execution receipt. Required tests include actual
embedded/main startup, a withheld committed ACK that blocks first work while
callbacks progress, late announce from a different control peer, unchanged
native idle/context admission, and the real credential-aware packet/stream
gates. Root owns schema generation, manifest custody and all proof actions.

R-N13 root released the separately verified development source at
`/srv/fast-local/jess/state/codex/omux-codex-owner-development-20261004/source`
after receipt `fae07b14-502e-4df6-b8f0-10dc06603792`. Implementation now adds
the exact C peer bridge copies and RAII Rust packet/stream wrappers, typed
private PeerWitness getters, app-server owner payloads/method exports, and
same-process endpoint startup in main/embedded app-server. The ordinary
app-server RPC dispatcher rejects both owner mutation methods and obsolete
WebSocket broker attach/detach. Original candidate bytes remain untouched.

The endpoint uses retained connections for at most eight bounded packets,
independent bounded workers, an absolute ten-second connection deadline and
an eight-second handler deadline. Typed payloads deserialize from the original
frame so duplicate authority keys cannot disappear in an intermediate JSON
map. Native callbacks pass their actual PeerWitness into core; core pins the
outgoing daemon witness before announcing and checks it on activation and
detachment, including duplicate detach. A changed daemon incarnation refuses
until explicit reattestation; same-UID claims do not reset that pin.

New Rust bridge tests exercise actual bidirectional private packets, truncated
packet refusal/cleared bytes, verified stream segments and the shared absolute
deadline. An endpoint parser regression rejects duplicate/unknown keys from
the original frame. These are written, not run, and do not replace actual
embedded producer/readiness/callback or delegated-writer proof. Root will
record formatting, current source hashes, schema regeneration and test receipts.

R-N13 security review found and released a necessary ordering fix: native
activation previously drained ancillary authority before its final core tuple
and daemon-peer check. The handler now calls core's nonmutating pending tuple,
original daemon witness and activity check before admission/drain, and the
final activation repeats that predicate atomically after asynchronous drains.
The embedded gate now prepares a real native thread and original registration
using generated private broker/capability files. Its actual outgoing verified
stream pins the daemon before a wrong-nonce callback. A separate actual child
process then sends the correct tuple over the verified packet carrier. Both
must refuse without entering the native admission/effect boundary. The
test-only discriminator counts that production boundary; it cannot supply a
peer witness, native reference, daemon pin or approved operation.

Root also required primary read-only owner/capabilities and owner/threads
inspection because ordinary embedded TUI has no WebSocket endpoint. The
implemented packet types return the actual verified process identity, bounded
native version and existing native capability shape, or actual ThreadManager
IDs with core-maintained thread/attachment generations. Inventory refuses
above 1,024 rows or a 64 KiB encoded packet. Unbound attachment generation is
reserved prospective metadata; it grants no authority and must match the
daemon-confirmed generation on activation. The ordinary app-server dispatcher
refuses these owner methods on its other transports as well.

The current candidate has one process-lifetime core owner registry. One
ordinary TUI/app-server process initializes one private endpoint and one
MessageProcessor; its multiple threads share that process identity with
distinct thread-instance generations. Multiple ordinary OS processes have
independent registries. This describes implementation scope, not passing
native-support proof. Creating a second MessageProcessor/embedded client
within the same OS process cannot replace the installed owner identity: its
new endpoint installation refuses, and configured owner work remains fenced.
Closing and reopening an embedded client in that process is therefore not a
supported owner-service lifecycle. A retained singleton with reviewed manager
registration/retirement is needed before broadening that scope.

Run the actual embedded endpoint/admission test in a fresh process with its
exact Rust test filter; its owned child callback fixture invokes only the
declared same test executable under that Bazel action. Separate fresh-process
bridge and core producer gates avoid inventing registry-reset authority.
Unfiltered shared-process embedded tests cannot be cited as a passing owner
lifecycle gate. No new test has been run by this worker, and no passing result
is inferred from the source changes.

R-N13 later portability release synchronized the candidate's C/header copies
to the reviewed Omux bridge: conditional modern Linux UAPI includes, scoped
fcntl header guards and SCM_PIDFD compatibility only for the complete modern
profile. Earlier peer receipts belong to earlier bytes. Root owns the declared
owner-linux toolchain/profile and new proof; no compile result is inferred.
Announce now also performs core's read-only private-path, capability, operation
and pending-conflict validation before native admission/drain, then final
preparation repeats activity/authority checks after the authorized drain.

Endpoint discovery remains scoped. The service generates a private
`codex_home/omux-owner-<opaque-prefix>/owner.sock`; ordinary startup registration
supplies this exact endpoint to the daemon. The current service does not
publish an independently discoverable rendezvous. Late attach and pre-startup
setup/discovery therefore require an explicit verified owner endpoint path.
The legacy default app-server.sock points to the separate app-server carrier
and cannot discover an ordinary embedded TUI merely because read-only owner
methods now exist. Automatic endpoint advertisement needs its own reviewed
publication/ownership design and proof.

R-N13 late-attachment review removed the pre-registration drain from announce.
After read-only input/loaded-thread validation, announce atomically reserves
pending custody with core's active/native/ambient-work checks, then initiates
the genuine producer RPC. Only the authenticated activation callback performs
native drains after daemon admission. There is no await/effect window between
pending reservation and the first daemon round trip that admits new unmanaged
work. Existing activity refuses without a drain; failed completion retains
pending/unresolved custody rather than ambient fallback.

The embedded gate now enters registration through actual owner/announce,
instead of preparing it directly. While the real outgoing daemon reply is
withheld, it submits a real native thread/shellCommand task, waits for the
native pending-registration work-barrier error and verifies a generated
private effect marker was never created. That actual task discriminator
complements the admission-entry counter and wrong-peer/tuple callbacks. It
does not infer provider handoff from a shell task; no test was executed here.

R-N13 root compilation `2b3d1df2` found duplicate generated response conversions
when register and announce shared the same Rust response type. The narrow fix
defines a distinct strict OmuxOwnerAnnounceResponse with identical wire fields,
uses it in the common method macro and maps actual successful endpoint
announcement to that type. Register's wire shape remains unchanged. Root owns
formatting, schema regeneration and the new compile/test receipt; this failed
attempt is not proof of any owner behavior.

The actual embedded announcement gate now ends with a positive control after
all rollback/no-effect assertions: a callback from the original pinned daemon
activates the exact tuple, the original protected producer stream receives
the strict registered/native_ref/operation_id reply, and the actual owner
endpoint returns the distinct typed announce response with every tuple field
checked. Local readiness is checked only after that producer reply. This
is a generated private fixture exercising producer/carrier decoding, not
proof of SQLite admission or live provider continuity. Root has not supplied
a passing receipt for this updated test.

R-N13 root compile `2b3d1df2` completed core production but found app-server
path/type errors. Startup now explicitly converts AbsolutePathBuf to PathBuf.
Native activation now asks MessageProcessor, the actual TurnCostWorker task
owner, to authenticate the full pending tuple/peer before calling its existing
shutdown_and_wait barrier. The thread handler repeats checks before ancillary
drain and final activation. This preserves awaited task cancellation instead
of treating its observation-only cloned handle as a task owner. No worker
source, stop API or task lifetime was weakened or changed; the unused endpoint
import was removed. Root owns formatting and the fresh compile/test receipt.

R-N13 focused run `1b2c` compiled the current Rust slice but the embedded gate
failed three attempts before its fixture broker accepted registration. Its
owned temporary home used tempfile's umask-dependent default directory mode;
only the broker socket and capability leaf had explicit private permissions.
Core's real registration validator also requires the immediate parent to be
private. The gate now explicitly sets its own home to 0700, without changing
production validation or admission. It also selects early announcement
completion against the unchanged bounded broker accept, so a refusal surfaces
directly instead of becoming an unrelated timeout. The held reply, actual
shell-task refusal/absent marker, distinct-process callback refusal and exact
successful announce decoder remain in the gate. The owner parser test still
requires a separate exact filter; the prior protocol filter selected no tests.
This fixture correction has not been executed by this worker; root owns the
fresh formatted-source run and receipt.

R-N13 exact embedded rerun `9a4422a0` reached the held producer request,
actual shell-task barrier and wrong-incarnation checks, then refused the
positive registration callback before any committed producer reply. Static
review with the core worker found the deliberate pending-work refusal emitted
an ordinary Other error; app-server marked that event as a native system fault,
so the strict idle admission check later saw SystemError. This requires a typed
expected admission-refusal notification, not relaxation or resetting of native
fault status. Root released the coordinated typed correction: this worker adds
the exact NativeOwnerPending v2 mapping in
`codex-rs/app-server-protocol/src/protocol/v2/shared.rs` and handles that variant
in `codex-rs/app-server/src/bespoke_event_handling.rs` by forwarding its error
notification before system-fault marking or accepted-turn summary mutation.
The core worker owns the protocol/core emissions and exhaustive mappings. All
other native errors keep their existing flow and the strict idle gate remains.
The actual embedded gate now requires the typed refusal, checks the generated
shell marker is absent, and reads real public thread metadata to require Idle
before the callback checks and positive activation.
The owned packet handler now emits only test-only static ErrorKind/timeout
diagnostics; the fixture logs no response body. The unreachable old broker
register/unregister handlers and their four imports were removed, preserving
read-only broker inspection and actual native owner handlers. No execution or
passing claim follows from these source changes.
