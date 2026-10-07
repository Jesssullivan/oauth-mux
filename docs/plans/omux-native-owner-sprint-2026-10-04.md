# Omux native owner and protocol sprint

Status: bounded acceptance passed; the reset remains experimental and unshipped.
The user selected native owner custody and Codex protocol, with native protocol
proof plus isolated installed Linux proof. This bounded sprint adopts and
elaborates the [owner proposal](omux-native-owner-custody-next-stage-2026-10-04.md)
under the [native reset](omux-native-account-lifecycle-reset-2026-10-02.md).
The [evidence record](../implementation/native-owner-evidence-2026-10-04.md)
contains the actual scoped results; requirements alone are not proof.

Start: `2026-10-04T08:28:06Z` / `04:28:06 EDT`.
Five-hour checkpoint: `2026-10-04T13:28:06Z` / `09:28:06 EDT`.
The [ledger](../../.goal/omux-native-owner-2026-10-04.json) records these dates;
prior deadlines and source-bound receipts remain unchanged.

## Product and selected scope

Install once, authorize sources once, and use ordinary terminal applications.
The resident daemon and thin clients remain the architecture. Applications do
not launch through Omux. Generic resource accounting, browser extension
acquisition without browser automation, grant renewal ownership, source
detachment and forget retain their existing contracts. This sprint supplies
native process ownership and a candidate protocol; it does not establish live
provider continuity, stock Codex support, a shipped fork or an achieved SLO.

The completed [admission checkpoint](../implementation/native-admission-evidence-2026-10-04.md)
remains a separate source epoch: 66 local tests, the isolated Sting installed
tuple and its exact artifact cannot prove new owner code. Preserve checkpoint
c73368fb and the original experimental Codex source, artifact and proofs.

## Ratified implementation decisions

Use a separate bounded Linux Unix SOCK_SEQPACKET owner-control endpoint with
64 KiB packets. Connection-origin credentials alone cannot prove the current
writer after a socket is delegated. Enable SO_PASSCRED and SO_PASSPIDFD before
connection acceptance; capture the retained connection-origin pidfd and validate
SCM_CREDENTIALS and SCM_PIDFD on every received packet before protocol parsing.
Protected adapter stream frames require equivalent verification on every
received segment. Reject changed writers, missing/truncated ancillary evidence,
unexpected passed descriptors and unsupported kernel profiles; close all
received descriptors on every branch. Native peers verify both directions.

The Linux profile requires runtime-supported 64-bit pidfs identity and namespace
evidence: boot identity, pidfs device/inode, user/PID namespace device/inode and
UID/GID. Retained kernel handles remain private and never become serialized FD
numbers. PID, pathname, endpoint absence and TTL are not liveness or terminal
authority. Darwin owner admission remains unavailable pending its own verified
reuse-safe profile. Ordinary control clients retain their existing redacted API.

An opaque 32-byte owner ID and four nonzero u64 generations identify adapter
epoch, endpoint generation, thread instance generation and attachment generation.
Wire generations use canonical decimal strings, rejecting zero, leading zeros
and overflow. Native operation IDs and process nonces are 32-byte opaque values
encoded as 64 hexadecimal characters. A versioned ACK matches the complete
owner/process/endpoint/thread/attachment/operation tuple. Labels never authorize
ownership. Owner incarnation rows use the immutable compound key
`(owner_id, adapter_epoch, endpoint_generation)`. The opaque owner ID remains
process-stable. A new epoch or endpoint creates a new row only after every prior
same-ID row is exactly retired; it never overwrites the original witness or
reuses the full key. All original-reference lookup and retirement checks use
the qualified key. An ID-only lookup refuses ambiguity rather than choosing
the newest row. Bound lifetime owner incarnation rows to 256 and combined
attachments and application-removal fences, including retirement records, to
4096. Never evict or reuse retired rows to make room.

Attachment generation selection scans the retained rows of the exact qualified
owner incarnation and thread instance. A new incarnation with no matching rows
starts at 1; older incarnation references and operations remain unchanged.
The native `owner/threads` attachment-generation value is only a latest-known
diagnostic hint. It cannot admit an attachment, select its authoritative
generation or resolve an uncertain operation.

The authenticated FileAuthority v2 checkpoint binds installation, sequence,
nonce, SQL snapshot revision and SHA256 of the exact stored metadata JSON under
the existing independent wrapping-key MAC. Reserve and fsync authority before
the atomic SQL checkpoint/metadata/operation commit; retain existing ahead-authority
poisoning. Fresh SQL schema version 3 seals exact initial metadata. Every legacy
v1 unsealed authority or SQL version 2 refuses with RecoveryMigrationRequired
before recovery callbacks, writes or effects. Do not automatically re-sign,
reinstall, discard history or regenerate the key. A usable legacy migration
remains a separate gate; the unshipped sprint chooses explicit refusal.

The seal proves retained original provenance, not process liveness, effect
completion or authorization to resume. Typed restoration retains unresolved
custody without retransmitting uncertain effects. Bind NativeRef to each native
binding, lease and request intent. Preserve the original application/native
session/request UUID namespace and two-attempt budget; adding owner to the key
would allow replay. Validate owner before duplicate, materialization, report and
restart fallback shortcuts.

Persist registration custody before first acquire. Actual ordinary Codex TUI
needs a native endpoint in its own in-process server; the standalone app-server
WebSocket is insufficient. Configured constructor-time pending state blocks
ambient and managed authorization, model/tool/background work and external readiness until
registration ACK. Publish the real thread in ThreadManager before registration
completion, then expose readiness. Unconfigured native construction retains its
ordinary behavior. Explicit preinstall late attach requires the owner endpoint
path; no automatic filesystem advertisement or endpoint discovery enrolls a
process. Late attach uses the same versioned producer. No registry/thread lock
may be held across daemon callback.

Ordinary TUI has no legacy WebSocket inspection endpoint either. Setup and
discovery therefore use read-only owner/capabilities and owner/threads over the
same credential-aware carrier. Capabilities bind the observed native version,
owner identity and protocol; they do not activate a grant or attachment.
Thread discovery has at most 1024 entries and must fit the actual 64 KiB packet;
oversize refuses before effects. Any unprepared entry or capacity failure refuses
the whole list; partial enumeration cannot hide missing preparation. Reserved
nonzero thread/attachment generation metadata is not daemon custody. Legacy
WebSocket inspection remains explicitly
read-only and cannot establish owner or mutation authority.

The daemon persists intent and admission credit, schedules bounded owned native
work and processes its completion through the actor queue. Native callbacks
must not deadlock behind the actor or thread-scope lock. Commit exact matching
ACK before releasing completion credit. Removal fences all retained native
attachments, including never-acquired threads; partial or unreachable owners
retain configuration and capability. Only original authenticated ACK and durable
terminal/cancellation evidence release custody. Never replay accepted streams or
tool execution.

Late attach retains its original operation on the wire and in the attachment,
credit and ACK. A fixed domain-separated internal registration mutation ID
distinguishes the inner registration transaction from the outer attach journal;
restoration recomputes that mapping. It does not rekey model requests or create
a fresh native effect/attempt. Codex configuration keeps its original installation
registry transaction across removal, with independent sealed capability and
removal-operation fences. A found registry after an uncommitted install cannot
be adopted by re-signing it.

The candidate pins subsequent broker calls to the admitted daemon incarnation.
A new daemon process therefore needs a separate explicit reconciliation protocol.
Real producer reconnection after daemon restart and reconciliation of uncertain
registration/detach effects remain unimplemented and held. Surviving synthetic
actor reports do not prove either producer reconciliation or continuity through
a daemon restart. Keep this limitation explicit until proved.

Account for the actual complete 16 MiB snapshot and permanent future row/phase
growth, plus separate per-effect completion bytes and record slots. Avoid
double-charging native rows or allowing unrelated mutations to spend reservations.

## File custody and workstreams

Root owns shared BUILD wiring, daemon ingress, plan/ledger/evidence/classification,
source staging, all execution coordination and final reconciliation. Reuse the
twelve authorized GPT-6.1 Sol workstreams with one writer per shared file.

| Workstream | Owned work |
| --- | --- |
| evening_authority | Native owner ledger, snapshot admission and ledger tests |
| evening_lifecycle | Engine actor, owner gates and native continuations |
| evening_install | Domain NativeRef and integration setup/removal gates |
| evening_vault | Storage/recovery v2 seal and actual crash/migration tests |
| evening_reapi | C peer bridge, private Zig witness and actual OS fixtures |
| evening_journey | Native owner probe/carrier and versioned ACK tests |
| evening_reliability | Original request authority constraints and no-replay tests |
| evening_codex | New candidate core authorization and readiness producer |
| evening_clients | Same-process app-server endpoint and real protocol schema |
| evening_security | Independent actual-path custody review |
| evening_graph | New candidate pristine source export and graph review |
| evening_linear | Sole dated tracker-comment writer after root release |

## Required acceptance

| Gate | Required current-source evidence |
| --- | --- |
| NO-PEER | Actual owned-process sockets reject delegated/current-writer changes, bad ancillary and unsupported profiles; bidirectional identity and restart attribution are genuine. |
| NO-ISOLATION | Two owners with the same native thread label cannot materialize, report, acquire or release each other's authority; original request namespace stays global. |
| NO-EARLY | Actual ordinary in-process producer blocks authorization/work/readiness until post-publication registration ACK; late attach retains original context. |
| NO-ACK | Exact complete versioned ACK and canonical full-u64 generation fields; stale/replaced/process-mismatched ACK cannot release custody. |
| NO-REMOVE | Never-acquired and partially detached owners remain fenced; restoration cannot bypass pending removal. |
| NO-CRASH | Actual storage/effect crash gaps and tamper refuse safely without effect retransmission or invented original authority. |
| NO-WORK | Actor/native callbacks and held thread-scope work do not deadlock, replay accepted work or reset attempts. |
| NO-CAPACITY | Production snapshot limits preserve completion bytes/slots, bounded owner history and retirement headroom. |
| NO-MIGRATION | Real legacy database/authority refusal leaves exact bytes and ciphertext intact; no silent conversion. |
| NO-RECONCILIATION | Necessary tests, eight candidate production labels, real generated schemas, isolated current-source Sting installed proof, tracker readbacks and durable source/context receipts agree. |

Use [evidence](../implementation/native-owner-evidence-2026-10-04.md) for actual
results. Unit predicates do not prove same-process live provider handoff.
Installed proof uses private XDG and a disposable genuine Secret Service, owned
daemon/CLI/offscreen Qt and cleanup. Interactive desktop/service and personal
vault evaluation are outside that tuple.

## Execution and external boundaries

Every executable/build/test/generator/package/check runs through locked Nix and
Bazel/Bazelisk, root-coordinated with explicit invocation IDs. Local sandboxed
execution is the default. No Just, standalone scripts, Zig build or restored CI.

The latest directly read lab board is R-C227. Its local pointer is absent in this
checkout; complete Linear readback is retained. Lab reports dated October 4
describe PZM Nix database corruption and full storage after failed serialized GC.
These are attributed lab observations, not Omux probes or authority to repair.
PZM GF REAPI remains held under TIN-2998/GF#1717 and its own coordinator;
quota volume, mTLS/JWKS, shared lock and 168-hour burn-in remain prerequisites.
No PZM service, GC, database recovery, Neo compilation or host takeover follows.

R-N13 governs every mutation receipt and durable session note. R-N11 forbids
signaling other agents or sessions. An actual R-N12 guard refusal stops its action.
No provider access/spending, personal vault access, upstream submission, signing,
site/release publication or support promotion is authorized by this sprint.
Reliability objectives and repository roles remain defined by their current
contracts; no contractual SLA or appointed human owner is inferred.
