# Proposed next stage: durable native owner custody

This is the original proposal and source-inspection snapshot. Its status and
implementation statements below describe that earlier epoch. Later
[admission evidence](../implementation/native-admission-evidence-2026-10-04.md),
[bounded owner evidence](../implementation/native-owner-evidence-2026-10-04.md)
and [installed interoperability evidence](../implementation/native-interop-evidence-2026-10-04.md)
record passing checkpoints. They supersede the prospective start gate below
within their stated scopes. This proposal does not ratify its broader requirements
or promote native resume, live continuity, stock support or daemon replacement.

Original proposal status (at drafting): **unimplemented and unratified extension**, 2026-10-04. R-N13 authorizes
this documentation mutation and its durable custody; it does not authorize an
owner protocol, runtime migration, provider access or a support claim. Root owns
document classification and indexing. No runtime, candidate or test source was
changed to create this proposal.

The [native reset](omux-native-account-lifecycle-reset-2026-10-02.md) remains the
active architecture. This document develops the proposed owner appendix in the
[evening plan](omux-native-evening-push-2026-10-03.md). The
[whole-snapshot admission sprint](omux-native-admission-sprint-2026-10-04.md)
must pass independent review and actual-path proof before implementation of this
extension starts. Neither a partial foundation pass nor this document ratifies
native ownership.

## Goal and bounded implementation boundary

Keep using ordinary native applications after reversible setup. Remember every
managed native instance and thread attachment, including attachments which have
never acquired a credential. Disconnect only the exact owner and attachment
generation whose native acknowledgment proves safe detachment. Preserve the
original request identity, two-attempt budget, accepted-work fence, native
history, tools and approvals throughout.

The smallest complete boundary crosses the daemon's private native channel,
durable owner admission, and a real versioned native hook. A daemon-only owner
table, an asserted PID, a new opaque ID in a fixture or a startup configuration
read cannot supply that boundary. The proposed first platform profile is Linux
with verified socket-derived process evidence; Darwin admission stays unsupported
until its separate peer/incarnation proof passes. Cross-host and Windows support,
automatic process-exit retirement and speculative mid-stream recovery remain
outside this stage.

## Inspected current source and proof scope

The candidate is pinned by [manifest.json](../../integrations/codex-upstream/manifest.json)
to official Codex commit `00c972ed5d6ff6499317fd41b7f23605b8e6850d`, tag
`rust-v0.157.0`, with product patch SHA256
`4a236da5663485458744375f8844898682d4b9f160fd37c00e912fd7cd2e76c3`.
The audited candidate source root is
`/srv/fast-local/jess/state/codex/omux-codex-source-00c972ed/source`.
The following are paths within that pinned root, not new implementation:

| Inspected path | Current boundary or missing predicate |
| --- | --- |
| `codex-rs/app-server-protocol/src/protocol/v2/thread.rs` | Broker protocol version 1 declares capability, register, unregister and thread-status types. Registration carries thread/binding/socket/capability-path fields; neither request nor acknowledgment carries an owner, incarnation, endpoint or attachment generation. Unregister acknowledges only `unregistered: true`. |
| `codex-rs/app-server/src/request_processors/thread_processor.rs` | Registration requires a loaded supported idle thread, drains ancillary authority and acknowledges refresh ownership. Unregister requires safe idle inspectable context. These predicates do not identify a previously registered process generation. |
| `codex-rs/core/src/auth_broker.rs` | Process-local registry maps native `ThreadId` to a broker binding. Native adapter RPC checks peer UID and shared application capability; it does not carry durable instance authority. |
| `codex-rs/core/src/client.rs` | Ordinary startup calls core registration from broker configuration. The broker stream creates one UUID before its two-attempt loop. Configuration-derived registration does not establish a durable daemon owner; no inspected native process-replacement mechanism restores that request UUID. |
| `codex-rs/app-server-transport/src/transport/unix_socket.rs` | Supplies the existing private control socket and WebSocket boundary. A versioned owner handshake and connection peer context are missing. |

Current Omux sources inspected are
[native_probe.zig](../../src/integrations/native_probe.zig),
[codex.zig](../../src/integrations/codex.zig),
[engine.zig](../../src/engine.zig),
[domain.zig](../../src/domain.zig),
[request_authority.zig](../../src/request_authority.zig), and the
[daemon](../../src/daemon.zig). Native probing verifies protected socket paths
and peer user identity: Linux reads `SO_PEERCRED` but uses only UID; Darwin uses
`getpeereid`. Listing, attachment and detachment open separate connections. The
engine's current binding identity is application/session/external binding, with
no native owner dimension. Request authority already preserves the original
application/session/request key and a maximum of two attempts.

[validation.json](../../integrations/codex-upstream/validation.json) retains the
current 17 focused broker predicates, the eight-production-target compile
`f76aed1e-36a7-4f9b-9c16-35cd91e9b4e0`, and complete prepared inventory
`916e727b-2b7d-43fa-a8be-663f9e325cee`: 8,515 tracked files and inventory SHA256
`d1516b7ca018277407de37b1af8463ae002e67cab7ac6664ecdbfe6fef9034a3`, with four
separately classified Bazel convenience links. Historical 55 broker and 318
protocol receipts belong to their recorded earlier patch epoch. None proves
this proposed owner protocol, platform incarnation checking or live continuity.
Stock Codex still lacks the required hook; `native_support` remains false.

## Required native identity and connection contract

A new negotiated hook version must provide a process-lifetime random nonce,
endpoint generation, and native thread-instance/attachment generations. The
nonce is instance metadata, not sufficient authentication by itself. Reading the
installed shared capability also does not prove instance ownership.

Both directions need verified OS peer evidence: the daemon's native control
connection and incoming trusted adapter requests. Pass peer evidence internally
from socket acceptance to the actor; never derive it from JSON PID fields. Admit
an owner only after these two channels are proven to belong to the same native
incarnation. The first profile admits one verified process; descendant workers
or delegated processes require an additional explicit authority contract.

Keep the verified control connection across observation and mutation, or verify
the exact saved incarnation and endpoint generation on every fresh connection.
Canonical private path, protected publication, connected peer and native nonce
must agree. A replacement socket at the same path is a refusal. Endpoint paths,
PIDs, versions and loaded-thread lists individually cannot authorize attachment,
release or retirement. Private paths and platform process metadata remain
private; owner controls expose opaque handles and bounded redacted state.

| Platform profile | Declared dependency and evidence requirement |
| --- | --- |
| Linux, proposed first profile | Existing pinned libc/socket toolchain, libcurl's connected native socket and `getsockopt(SO_PEERCRED)` plus `SO_PEERPIDFD`. [Linux v6.5 kernel source](https://raw.githubusercontent.com/torvalds/linux/v6.5/net/core/sock.c) obtains the latter from the socket's retained kernel peer PID rather than a fresh numeric PID lookup. Hold that handle while verifying bounded peer incarnation metadata and the native nonce. Kernel availability, namespace mapping, permissions and reconnect/restart races need actual version-bound tests. A serialized FD number or PID alone is not durable identity. Missing proof refuses admission. |
| Darwin, blocked profile | Existing `getpeereid` checks user identity. Apple's [public Unix socket header](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/un.h) exposes `LOCAL_PEERPID` and `LOCAL_PEERTOKEN`, but the inspected [XNU implementation](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/kern/uipc_usrreq.c) obtains the token using `proc_find(peerso->last_pid)`. That source observation does not establish a reuse-safe incarnation. Exact SDK audit-token interfaces, any required system audit library linkage, socket transfer/delegation semantics and PID-reuse races need a dedicated reviewed profile before support. |

These primary OS sources inform a proposed contract. They are not the locked
build inputs or proof for an installed kernel/SDK. Existing declared Apple SDK
14.4 and Linux execution closures are not changed by this document. Any required
header, library or C bridge additions must enter the locked Nix/Bazel graph and
receive their own closure/source review. This audit made no host process calls,
signals, OS probes or provider requests.

## Durable owner and request authority

The proposed ledger stores opaque owner ID, application, adapter epoch, verified
private process/endpoint witness, native thread ID, attachment generation,
original operation ID and phase. Phases distinguish pending registration,
attached, pending detach, unresolved and detached. Retired owner/thread
generations leave tombstones which reject delayed acknowledgments, registrations
and releases. These tombstones do not revoke provider grants or replace
account-forget tombstones.

Proposed initial ceilings are 256 owners and 4,096 attachment/retirement records;
these are design limits awaiting ratification, not current capacities. Count
live, unresolved and retired authority together. Refuse at capacity; do not evict
authority by TTL. Reserve actual worst-case serializer bytes and per-list slots
for every success, failure, uncertainty and tombstone outcome, including the
credit metadata, within the existing complete 16 MiB admission envelope before
any native effect. Other writers must preserve those obligations.

Persist a bounded typed original witness, immutable generations, operation ID
and credit before issuing registration or detach. An operation fingerprint alone
cannot reconstruct an input-dependent reconciliation plan. Native I/O must not
hold the actor while awaiting a synchronous callback into that actor; use bounded
adapter work and actor continuations, or a protocol whose acknowledgment needs
no reentrant callback.

The current storage boundary authenticates grants and independent installation
checkpoint lineage; it does **not** MAC the complete metadata JSON. This proposal
does not call a private typed snapshot cryptographically authenticated. Before
owner recovery can confer authority, review how its original peer attribution,
generation and admission fence remain bound to trusted installation/checkpoint
state. Any additional seal or trusted schema marker needs a separate explicit
storage and migration design. Self-consistent mutable metadata cannot invent a
verified peer witness. The first implementation must refuse recovery authority
where that proof is missing, rather than ship a fabricated owner stub.

Keep the request key exactly `(application, native session, original request_id)`.
Owner and attachment generation constrain the retained immutable intent; they
must not create another work-key namespace. Namespace route binding identity and
metadata/materialization/release by verified owner and exact thread generation
so two processes resuming one native thread cannot overwrite each other's route.
A different owner presenting retained work is a mismatch, including when the
first attempt was safely rejected. Neither registration nor a daemon epoch
change resets the original two-attempt budget.

Native logical-request identity must remain unchanged through safe alternate
selection and ownership reconciliation. Registration retries use their separate
stable operation ID and never rerun a model request. Accepted, completed,
abandoned or uncertain work cannot be reacquired under a fresh UUID. The current
native UUID survives the inspected in-process retry loop; native process-restart
continuation remains unsupported until a separate retained original-work
contract proves that it does not manufacture fresh replay authority.

## Registration, disconnect and no-resume fence

Ordinary startup and late attachment share the following sequence:

1. Verify native version, negotiated owner capability, exact process/endpoint
   witness and thread generation; prepare every bounded outcome and reserve it.
2. Commit pending owner registration and original operation authority before
   native managed-mode activation, including threads with no acquire history.
3. Issue the exact native registration. Activate only after an acknowledgment
   matching owner, process nonce, endpoint generation, adapter epoch, thread and
   attachment generation. Persist the outcome before releasing unused credit.
4. A lost or mismatched acknowledgment retains unresolved custody and its credit.
   Older hooks report the missing capability. A configuration read cannot
   substitute for registration.

Disconnect first commits a stable removal operation and an epoch-bound admission
fence. It excludes new owners, thread attachments and leases while preserving
existing accepted-work custody and scoped terminal-report authority. Enumerate
all required retained owners. Each detach must target the original verified
connection/incarnation and acknowledge the exact owner/thread generation and
operation. Preserve existing native idle, ancillary-ownership and opaque-context
checks; a generation match does not make unsafe native state portable.

Partial detach, unreachable owners, endpoint replacement and uncertain replies
remain pending. Configuration restoration and shared capability-epoch retirement
wait for all required acknowledgments and request/lease fences. Reattachment uses
a new explicit attachment generation and cannot resurrect retired authority.

On daemon restart, retained attached/pending owners become unverified or
unresolved. Preserve original request/mutation fences, typed witnesses, credits,
tombstones and ciphertext. **No effect-resumption path is authorized by retained
phase alone.** Never redispatch an uncertain registration, detach or model call
because the owner is absent, a PID was reused, a directory is empty, a credit was
released, or a socket disappeared. A future reconciliation implementation needs
its own reviewed original-witness and acknowledgment protocol; absence is not
terminal evidence. Proven surviving owners may retain original scoped terminal
report authority without replacement work. Automatic exit retirement is deferred.

Migration must be explicitly versioned and gated before effects. Preserve legacy
request keys, attempts, mutation IDs, ciphertext and independently valid grants.
Mark ownerless legacy bindings unresolved; do not infer their owner from today's
endpoint or rekey them into a fresh request budget. Unknown, overcommitted or
unverifiable legacy obligations refuse conversion. No automatic native resume or
ownership activation follows migration.

## Implementation and fresh proof required

The Rust candidate must change the real core broker registry and request
parameters, ordinary startup in `core/src/client.rs`, app-server thread handlers,
control transport peer context and protocol types. Proposed capability/version
and owner fields are not existing wire methods. Regenerate JSON and TypeScript
schemas through declared exporters. Keep ancillary authorization draining,
access-token-only materialization, native context checks and the original request
UUID/attempt loop intact. No Omux launcher or copied native session store is
introduced.

Omux implementation crosses private channel peer context, native probe
connections, actor owner admission, binding/request constraints, whole-snapshot
credits and explicit storage/migration validation. It must not be implemented as
an isolated advertised owner type with no verified native producer.

| Proposed acceptance | Required actual predicate |
| --- | --- |
| NO-PEER | Private OS sockets prove same-incarnation ingress/control identity; wrong user, unsupported proof, PID reuse, socket replacement and delegation refuse before effects. Synthetic claimed PID fields cannot authorize an owner. |
| NO-ISOLATION | Two real private native endpoints load the same thread ID; detaching A preserves B's route, materialization and attachment generation. |
| NO-EARLY | Registration before any acquire, including lost reply and restart, retains durable custody which removal must resolve. Ordinary startup follows the same authority path. |
| NO-ACK | Wrong owner/process/endpoint/epoch/thread/generation acknowledgments and delayed retired-generation callbacks cannot activate or release custody. |
| NO-REMOVE | Registration/lease races after the persisted removal fence refuse. Partial/unreachable/unsafe owners retain configuration and capability; existing terminal reports retain their scoped authority. |
| NO-CRASH | Before/after effect/ack/commit crash boundaries preserve original operations, credits and uncertainty. Restart does not repeat an effect or infer detach from absence. |
| NO-WORK | Accepted/unknown work and first/second-attempt history survive owner replacement and migration. No fresh request namespace or UUID can reopen the original work. |
| NO-CAPACITY | Actual production-envelope and record-slot saturation refuse before registration/detach, including maximal private metadata escaping and required retirement outcomes. |
| NO-MIGRATION | Ownerless, unknown-version, tampered/ambiguous or overcommitted authority refuses conversion without deleting ciphertext, old fences or history. Recovery cannot invent verified peer attribution. |

These proposed IDs identify future predicates and have no passing receipts.
Actual platform process tests, native protocol conformance and failure fixtures
must accompany model tests. Version-bound live ordinary launch, native resume,
same-process account handoff and preserved native state remain additional
[native-adapter](../spec/native-adapter-contract.md) gates; fixture acknowledgments
and compilation do not prove them.

A changed Rust candidate requires a separate artifact epoch and fresh exact-source
inventory, focused core/transport/app-server/protocol tests and generated-schema
checks. Compile the same eight production labels: core, app-server, config,
app-server-protocol, TUI, CLI, config-schema and PublicSchema bundle. Record any
inherent schema helper actions separately. Current candidate/source receipts
remain unchanged history and cannot be inherited as proof of new bytes.

All implementation, generators, builds and tests require root-coordinated locked
Nix/Bazel actions, minimal environments and declared inputs. R-N11 forbids
signaling other sessions; an actual R-N12 guard-hook refusal stops the action and
requires its stated escalation. This documentation authorizes no host/service
activation, provider access, personal credentials, Rust source changes, live
evaluation, publication or REAPI gate change.
