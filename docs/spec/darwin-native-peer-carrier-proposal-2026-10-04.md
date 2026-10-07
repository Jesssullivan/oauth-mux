# Proposed Darwin native peer carrier

Status: **proposed, unimplemented and unproved**, 2026-10-04. R-N13 authorizes
this contract proposal only. The [native reset](../plans/omux-native-account-lifecycle-reset-2026-10-02.md)
owns architecture; the [native adapter contract](native-adapter-contract.md)
owns existing interfaces. This proposal creates no wire method, platform profile,
runtime permission or supported capability. Root owns authority registration and
all subsequent declared checks. No executable, host probe, SSH transport,
service activation, REAPI selection or provider action was performed to author it.

## Current boundary and proposed outcome

The canonical [C bridge](../../src/platform/native_peer.c) supports a Linux
pidfs profile; its Darwin entrypoints return `Unsupported`. The current
[header](../../src/platform/native_peer.h) and [Zig witness](../../src/platform/peer.zig)
encode Linux pidfs and namespace identity. Darwin must have a separately reviewed
profile, rather than filling those fields with invented substitutes. The current
Linux owner carrier is Unix `SOCK_SEQPACKET`; its positive fixtures and installed
Linux receipts do not transfer to Darwin.

The proposed outcome is authenticated, bounded owner communication in both
directions between the resident daemon and the exact native producer incarnation.
Every owner-bearing request and acknowledgment must identify its current OS
sender before protocol bytes are interpreted. This includes credential-bearing
adapter ingress as well as owner-control replies. A new protected owner channel
alone cannot make an existing UID-only adapter stream safe.

Preserve the original owner ID, process nonce, adapter epoch, endpoint generation,
thread-instance generation, attachment generation and operation ID. These remain
typed native metadata, never substitutes for OS attribution. Keep original request
identity and the two-attempt budget; accepted work, streams and tools cannot be
replayed. Omux-developed application adapters and version-bound delivery,
automatic discovery, ordinary launch/resume and live same-process continuity
retain their independent acceptance gates.

## Carrier candidate and unresolved proof obligations

Investigate a dedicated Mach message carrier requesting audit trailers, with a
bounded inline body, a retained endpoint right and an authenticated reply path.
This is a candidate architecture, not a selected implementation. The existing
owner handlers may eventually share typed logic behind a transport abstraction;
the existing Unix endpoint and durable witness ABI cannot silently change.

Apple's [Mach message header](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/osfmk/mach/message.h)
declares audit trailers and treats audit tokens as opaque values interpreted by
BSM APIs. The inspected [kernel message implementation](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/osfmk/ipc/ipc_kmsg.c)
initializes sender audit data from the sending task. These source observations
justify evaluating per-message attribution. They are mutable primary-source
locators, not pinned SDK inputs or proof of PZM's installed kernel.

The actual immutable SDK 14.4 contains `mach_msg_audit_trailer_t`,
`MACH_RCV_TRAILER_AUDIT` and public `audit_token_to_pidversion`/UID/PID accessors
in `usr/include/mach/message.h` and `usr/include/bsm/libbsm.h`. Presence of an
accessor does not prove uniqueness or a safe connection origin. Review the exact
send/receive path, user-supplied trailers, trailer placement/size, right transfer,
receive-right replacement, exec, departure and process-ID/version reuse before
accepting this candidate.

PID plus PID version is not ratified durable incarnation authority. A finite
version field and an endpoint right cannot be assumed collision-free or owned
by the original receiver. The inspected [XNU process identity code](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/kern/kern_proc.c)
uses unique process identity as well as PID/version when comparing process
identities. Establish a supported, race-safe userspace mechanism, or a reviewed
equivalent which satisfies the same obligations. A fresh numeric PID lookup
without atomic token binding is insufficient. If the exact SDK/kernel cannot
provide this boundary, Darwin owner admission remains unsupported.

The inspected [Unix implementation](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/kern/uipc_usrreq.c)
marks Unix `SOCK_SEQPACKET` as unimplemented and resolves `LOCAL_PEERTOKEN` through
`proc_find` on the socket's numeric peer PID. Consequently a socket option or
Linux carrier name cannot establish reuse-safe current-writer attribution on
Darwin. `getpeereid`, executable UUIDs, shared capability bytes, JSON PIDs and
native nonces alone remain insufficient. Neither libcurl WebSocket reads nor a
second reader on the same stream supplies per-message audit evidence.

Endpoint publication is an unresolved part of this proposal. A private,
authorized discovery descriptor must resolve to a retained endpoint in the
correct per-user bootstrap context. It must detect endpoint replacement and
bind fresh replies to the original native incarnation. A path, bootstrap name
or port number by itself is not authority. Publication must not require arbitrary
service activation, global namespace registration or changes to another owner's
launchd services. No publication mechanism is selected here.

## Proposed internal interface and resource contract

These are semantic interface requirements, not exported C/Zig/Rust signatures.
Before implementation, review a common adapter interface and distinct Linux and
Darwin context representations with the lifecycle, storage, producer and security
owners. Preserve existing callers until an explicit migration is ratified.

| Proposed operation | Required behavior |
| --- | --- |
| Open verified context | Resolve an authorized private endpoint, retain owned kernel rights, complete a bounded bidirectional handshake and construct an opaque live context from actual OS evidence. No constructor accepts caller-supplied witness/PID/token fields. |
| Receive verified message | Receive body and kernel attribution together; validate exact envelope/trailer before parsing. Match the current sender against the original verified incarnation on every message. Only success exposes the body. |
| Send bounded request/reply | Use the one owned carrier, fixed protocol bounds and absolute caller deadline. Bind response correlation and echoed native generations without treating send success as effect completion. |
| Duplicate evidence ownership | Retain the necessary owned kernel rights for queued actor work without introducing another receiver or borrowing the caller's lifetime. |
| Inspect witness | Return an immutable, bounded profile-tagged value for original provenance. Durable structural validation cannot create a live context. |
| Close context | Release all owned rights, buffers and any out-of-line resources on success, rejection, cancellation or deadline. Closing evidence is not retirement authority. |

Propose the existing owner payload ceiling of 64 KiB, plus a separately checked
fixed envelope/trailer allowance. Propose inline bodies with no out-of-line
memory or arbitrary port descriptors. If handshake reply rights are required,
enumerate their exact count, disposition and lifetime before implementation;
reject every other descriptor. Receive errors must destroy delivered unexpected
rights/resources rather than leaking them. Queue and message-count limits need
explicit actor integration; a single receiver owns each context.

A packet is validated in full before any owner effect. Malformed or changed
peer evidence closes the protected conversation and discards partial/preexisting
frames. Deadline/cancellation and lost replies leave uncertain operations
unresolved; they do not imply failure, safe retry, detach or replay permission.

The proposed durable Darwin witness must include a reviewed profile/schema
version, independently obtained boot identity, supported reuse-safe incarnation
evidence and required user/session/bootstrap scope. Its exact fields and equality
rule remain blocked on the OS review above. Do not persist live port/FD numbers,
cast audit-token bytes into Linux fields, or accept saved witness bytes as live
authority. A changed witness schema requires explicit storage/seal migration
review. After daemon restart, retained custody stays unresolved until fresh
bidirectional evidence matches the original witness and native reference.

## Failure and actual-process acceptance matrix

All rows below are proposed mandatory predicates. None is a passing receipt.

| Trigger | Required outcome and fixture discriminator |
| --- | --- |
| Unsupported SDK/kernel/carrier | Typed unsupported refusal before owner or credential effects; no UID/PID-only fallback. |
| Wrong user, bootstrap scope or boot | Refuse before parsing; distinguish actual authenticated scope mismatch from a caller assertion. |
| Missing, malformed or short audit trailer | Discard bytes and close; forged body fields cannot repair OS attribution. |
| Inherited/transferred sending right | An actual second process writes; current-message sender mismatch refuses even with copied nonce/generations. |
| Transferred receive right or relay | Fresh reply must not authorize a different receiver/forwarder; audit exact reply-chain and origin binding. |
| Reconnect, endpoint replacement, exec or PID/version reuse | Same reviewed incarnation succeeds where allowed; replacement refuses. A forced-reuse gate or equivalent reviewed discriminator is necessary. |
| Wrong generation or delayed acknowledgment | Exact owner/reference/operation mismatch refuses before changing durable state. |
| Oversized/complex message or unexpected rights | Bounded refusal; delivered rights/out-of-line resources are reclaimed on every path. |
| Peer departure, queue saturation, timeout or lost reply | Preserve bounded ownership and unresolved custody; no inferred retirement or accepted-work replay. |
| Daemon restart or restored snapshot | Saved witness remains provenance only; fresh OS proof is mandatory before effects. |

Actual fixtures must create endpoints in the native producing process, prove both
directions, exercise two real sender processes and report resource cleanup.
Synthetic trailer structs can test parsing but cannot prove sender identity.
No personal vault, native session, provider, unrelated process or service is
part of these proposed private fixtures.

## GF/PZM dependency and provenance gate

The [Apple runbook](../runbooks/omux-apple-toolchain.md),
[host custody](../../tools/nix-workers.md) and
[handoff](../implementation/native-safety-evening-handoff-2026-10-03.md)
remain authoritative for the held compiler lane. Neo is orchestration/read-only
input source; PZM is the intended Darwin compiler host. This proposal neither
releases GF's hold nor permits a manual SSH compiler or an alternate route.

| Dependency | Current evidence and required release predicate |
| --- | --- |
| External owner | User-attributed `gf-core-adoption-orchestration`, TIN-2998/GF#1717. Local lab `nix/darwin/petting-zoo-mini.nix` declares `startServices=false`. GF must supply its explicit owned readiness release; an advisory hook is not release authority. |
| Activation prerequisites | Dedicated 4 GiB APFS quota volume, mTLS/JWKS custody, shared operation lock and fixed 168-hour burn-in evidence. Credential contents remain private. These cannot be promised complete within this five/ten-hour sprint. |
| Store/transport | Historical Omux SSH-ng failures and later attributed lab storage/database incidents retain their epochs. Current healthy store capacity, authenticated authorized transport and client authority remain required; no GC, database repair or service change follows from this proposal. |
| Exact execution closure | `/nix/store/9k958iwyvk7cn5f7axdfg8a0j1s0nsa1-omux-bazel-closure`; prior coordinator receipt reconciled 128 registered paths, including 126 declared members. Complete matching PZM membership, NAR/reference validation and registration identity remain prerequisites; historical coordinator success is not fresh worker proof. |
| SDK/compiler inputs | `aarch64-darwin`, authorized Apple SDK 14.4, Swift 5.10.1 and the locked Omux compiler/Zig/Bazel graph. SDK root is `/nix/store/rcqgjj8hphkhqark1ibiwfaa7yrzniz3-apple-sdk-14.4/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk`. Any BSM/system library linkage must become explicit declared inputs. |
| Hardware/OS profile | Real PZM arm64 Mac; exact macOS build, XNU release/source commit, architecture, execution user and relevant bootstrap/sandbox context. Bundle minimum macOS 14.0 is compatibility metadata, not proof that the proposed owner profile works on every supported bundle OS. |
| Worker/toolchain policy | Inspected lab module defaults to Chapel policy `chapel-ab552d8` and a distinct worker closure digest. GF must independently establish an Omux-compatible exact-closure route; pool/property labels do not prove selected worker identity. |
| Capacity/sandbox compatibility | Inspected module defaults: 64 MiB bundle/blob, 2 GiB materialized input/200,000 nodes, 32 MiB output, 8 GiB sampled RSS, one concurrent action, 30-minute execution deadline. Compare current analyzed action inputs against these and validate required Mach rights/IPC in the actual sandbox. Prior 3,151,018,144 NAR bytes are not an action-input measurement. Do not enlarge operator limits implicitly. |
| Selected-worker provenance | Bind operator executor/cache/instance/auth context, exact `nix_closure`, worker identity and independently selected worker receipt. Submitted platform properties alone do not establish routing. Endpoints/auth material stay outside source. |
| Fresh executed proof | Current-source graph, executed input digests, cache distinctions, remote-only/no-fallback execution, actual artifact hash/bytes and bounded cleanup receipt. Analysis and prior-source receipts cannot stand in for these predicates. |

The local lab sources above are inspected declarations, not current host
observations. Mutable Apple source URLs are reference locators only. Before
runtime admission, record an immutable XNU source tag/commit corresponding to
the observed macOS build, exact SDK header/library identities and the same
source/toolchain tuple as each actual gate. An unavailable mapping remains an
explicit proof gap; do not invent an XNU version from SDK 14.4.

## Five-hour readiness and conditional ten-hour proof

The five-hour deliverable is a reviewed proposed carrier, explicit unresolved OS
obligations, typed refusal/interface specification, private fixture plan and
declared-input/route dependency inventory. Root may perform authorized local
contract/analysis checks through locked Nix/Bazel. None dispatches Darwin tools
or changes the held worker. Preserve `native_support: false` and unsupported
Darwin owner admission.

The ten-hour path is conditional on independent GF release, store/route/SDK
qualification and ratification of a reuse-safe profile. Its order is actual
private peer/carrier fixtures, exact producer/daemon interoperability, current
Darwin compile/archive and separately authorized installed app/vault/service
gates. Do not skip peer refusal gates to obtain an archive. Ad-hoc bundle signing
does not establish Apple platform acceptance, Developer ID or notarization.
If prerequisites remain held, finish source/contract readiness and continue
authorized qualified Linux work; no sprint deadline expires the hold.

Existing carriers suffice: TIN-1798/TIN-2723 for peer/native protocol and daemon
ingress, TIN-2050 for exact provenance, TIN-5340/TIN-2830 for separate Darwin
custody/delivery, TIN-5342 for measurement and TIN-2057 for later live continuity.
TIN-2998/GF#1717 remains GF's external dependency. No new assignment, ticket
mutation or service ownership is created here.

Apply [REL-003/004/007](../reliability/service-objectives.md): zero integrity
budget, encrypted/vault custody and safe restoration. Measure by exact OS,
artifact and native version. Short fixtures prove their predicates; they do not
establish achieved SLOs, ordinary-launch continuity, stock native support or a
staffed SLA.
