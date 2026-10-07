---
title: Native owner OS peer and socket custody review
date: 2026-10-04
status: active_source_review
summary: Source-only review of Linux incarnation witnesses, writer attribution, native socket custody and libcurl ownership.
refs:
  - R-N11
  - R-N12
  - R-N13
---

R-N13: root assigned this independent review and this note as the only writable
file. No implementation, build, test, process probe, host transport, service,
provider or tracker action was performed. Root owns declared locked Nix/Bazel
proof. The user-selected owner/Codex protocol sprint does not release the GF-held
PZM worker or its four prerequisites. Darwin owner admission remains unsupported
until a separately reviewed reuse-safe peer profile passes its own proof.

The [owner proposal](../plans/omux-native-owner-custody-next-stage-2026-10-04.md)
and this review describe proposed predicates, not shipped support. Stock native
Codex and live ordinary launch/resume/same-process continuity remain separate.

## Current implementation gaps

[daemon.zig](../../src/daemon.zig) checks `SO_PEERCRED` on Linux and `getpeereid`
on Darwin. Linux discards PID/GID and compares only UID. Both the outgoing daemon
client and accepted connections use this user check. `Job` retains stream,
channel and deadline; `dispatchUntil` receives channel and JSON without an OS
process witness. Rechecking the same UID on each control slice does not identify
a process incarnation or the writer of later bytes.

[native_probe.zig](../../src/integrations/native_probe.zig) similarly compares
only UID. It resolves protected parents and a final private socket/symlink, but
libcurl performs the WebSocket upgrade before `CURLINFO_ACTIVESOCKET` is verified.
Observe/list, attach and detach create separate connections. A safe pathname,
shared capability, declared version, thread ID or claimed nonce cannot make a
fresh connection the previously observed process. Socket replacement between
path inspection and connect must be caught by connected peer/generation proof.

[tools/native.h](../../tools/native.h) exposes socket/libcurl headers but no peer
bridge. The current C implementation in `native_api` is the vault bridge, not a
process witness implementation. `file_metadata.zig` provides normalized
descriptor metadata; that alone does not distinguish legacy anonymous-inode
pidfds. A dedicated small peer bridge should normalize the libc ABI rather than
copying Linux C structures or socket constants into Zig/Rust.

## Declared source and runtime boundaries

`flake.lock` pins nixpkgs `0726a0ecb6d4e08f6adced58726b95db924cef57`.
The Linux Zig target ABI is glibc 2.42. `flake.nix` pins libcurl 8.22.0 with source
SHA256 `f7ef3ae8a22e521f289803fe93543eb64c329b58aa73a9e224dfd915a2a5f4f7`.
The build consumes the selected closure's libc development headers. Read-only
inspection of the existing native-proof external repository's `native.json`
records `/nix/store/fbbw928argckfii0j322346ihmllg7a7-glibc-2.42-61-dev`
and ABI 2.42. Those exact headers declare `SCM_PIDFD`,
`SO_PEERPIDFD`/`SO_PASSPIDFD`, `PID_FS_MAGIC` and namespace pidfd ioctls. The
external metadata observation is source custody, not a fresh compiled result;
root must bind the bridge compilation to the actual current declared inputs.
The flake does not pin the installed running kernel. Header presence never proves
that a kernel implements an option or that namespace access is permitted.

Linux [v6.5 socket source](https://raw.githubusercontent.com/torvalds/linux/v6.5/net/core/sock.c)
obtains `SO_PEERPIDFD` from the socket's retained kernel peer PID, without a fresh
numeric PID lookup. The same release contains `SO_PASSPIDFD` and
[SCM_PIDFD delivery](https://raw.githubusercontent.com/torvalds/linux/v6.5/include/net/scm.h).
These identify a referenced kernel process, but do not by themselves define a
portable equality test. Legacy v6.5 pidfds use
[anonymous inodes](https://raw.githubusercontent.com/torvalds/linux/v6.5/kernel/fork.c);
comparing their `fstat` inode values can falsely equate different processes.
Holding a pidfd does not prevent numeric PID reuse after the process exits:
[PID retirement](https://raw.githubusercontent.com/torvalds/linux/v6.5/kernel/pid.c)
removes numbers from the PID allocator independently of outstanding references.

Linux [v6.9 pidfs](https://raw.githubusercontent.com/torvalds/linux/v6.9/fs/pidfs.c)
uses a process-associated inode on a filesystem with `PID_FS_MAGIC`, and creates
new handles from that process's stashed path. Its
[64-bit PID allocation](https://raw.githubusercontent.com/torvalds/linux/v6.9/kernel/pid.c)
assigns the process a separate monotonically allocated inode identity.
[v6.18 pidfs](https://raw.githubusercontent.com/torvalds/linux/v6.18/fs/pidfs.c)
explicitly documents inode comparison on 64-bit systems. A new pidfd for the same
still-live process can therefore match after daemon restart; no raw fd number is
durable identity. Boot identity must also match to reject identity reuse across
reboot. Restrict this proposed profile to 64-bit Linux; 32-bit inode generation
and wrap semantics require another review.

[v6.11 pidfs](https://raw.githubusercontent.com/torvalds/linux/v6.11/fs/pidfs.c)
adds pidfd namespace ioctls, absent from the inspected v6.10 implementation.
They resolve the referenced task, require read permission, and can refuse exited
or inaccessible peers. The complete proposed same-user/PID-namespace profile
therefore has an upstream API floor of Linux 6.11, with feature checks and actual
kernel-bound tests still required. Kernel release text alone is insufficient,
especially for backports or modified kernels. No numeric `/proc/<pid>` lookup or
`pidfd_open(claimed_pid)` fallback is approved by this review.

## Connection origin and actual writer are separate

Linux [Unix socket source](https://raw.githubusercontent.com/torvalds/linux/v6.5/net/unix/af_unix.c)
captures listener credentials at listen and connecting credentials at connect.
An inherited or transferred socket continues to expose that origin. Merely
declaring delegation unsupported cannot detect a later child or unrelated
process writing through the original descriptor.

The proposed first owner profile must enable `SO_PASSCRED` and `SO_PASSPIDFD`
before any relevant bytes can arrive and use `recvmsg` on every received stream
segment. Validate kernel-provided `SCM_CREDENTIALS` and `SCM_PIDFD`, matching the
writer's pidfs identity to the saved socket-origin identity before framing or
parsing owner-bearing requests and acknowledgments. Linux
[v6.18 stream receive](https://raw.githubusercontent.com/torvalds/linux/v6.18/net/unix/af_unix.c)
keeps different writers' credential segments separate. Partial frames must retain
their verified writer attribution; a mixed-writer continuation rejects the whole
frame. Apply the same rule on native control and trusted adapter ingress, in both
receiving implementations.

Missing or duplicate required ancillary fields, negative pidfds, truncated
payload/control data, namespace mismatch, changed origin/writer, unexpected
descriptor rights, unsupported options and unavailable evidence all refuse
before effects. Use bounded payload/control storage and `MSG_CMSG_CLOEXEC`.
Close every delivered `SCM_RIGHTS` or `SCM_PIDFD` descriptor on rejected or
truncated messages, including descriptors encountered before the rejecting
field; do not retain unexpected rights. The
[kernel delivery code](https://raw.githubusercontent.com/torvalds/linux/v6.18/net/core/scm.c)
can report truncation or a failed pidfd instead of complete evidence. Its
credential checks also permit privileged spoofing: this profile is a boundary
against nonprivileged peer substitution, not a claim against kernel/root or
namespace administrators authorized to forge credentials. Namespace equality
and the applicable threat-model privilege boundary must be explicit.

## Minimal proposed bridge and private types

Add a declared `peer_bridge.c`/`.h` through the existing native API graph, with
Linux implementation and an explicit unsupported result elsewhere. Suggested
operations are capture-from-connected-fd, bounded verified receive, compare
incarnation, inspect liveness without signaling, and close. Closed status enums
distinguish unsupported, permission, malformed/truncated ancillary, wrong user,
namespace mismatch, departed process and changed incarnation. No raw diagnostics,
process command lines or unrelated host enumeration belong in this bridge.

Capture `SO_PEERCRED` and `SO_PEERPIDFD` with exact result sizes. Confirm pidfs by
`fstatfs` before using descriptor device/inode equality. Obtain peer user/PID
namespace handles from pidfd ioctls and compare them with the daemon's declared
namespace context; inaccessible or different namespaces refuse the first
profile. Check process exit readiness without signaling. Keep the socket and
pidfd under one explicit owner, with cleanup on every cancellation/error path.
No fall back to UID-only admission is allowed when these operations fail.

`PeerContext` is runtime-only, opaque outside the OS boundary, and constructed
from actual descriptors. Carry it from accepted socket/verified native connection
through the worker result and actor invocation. `VerifiedPeerWitness` combines
that OS context with the negotiated native nonce and exact adapter, endpoint,
thread-instance and attachment generations. The actor compares both directions'
incarnation identities; matching JSON cannot construct the witness. A distinct
`ConnectionGeneration` prevents stale connection completions from replacing a
newer verified channel. The native nonce identifies protocol generation, not OS
authentication or executable attestation.

Proposed bounded original OS witness fields are profile tag, boot ID (16 bytes),
pidfs device/inode (64-bit), user/PID namespace device/inode identities, and
verified UID/GID. PID is optional private observation and never the equality
key. Native nonce/generations remain separately typed. Retained namespace handles
support runtime comparison; their recorded numbers alone are not a new trusted
constructor. Persist only the bounded original provenance in the reviewed sealed
metadata/checkpoint contract; never persist an fd integer as authority. After
restart all attached/pending rows are unresolved until fresh OS/protocol evidence
matches the trusted original witness. Boot mismatch, unavailable peer or socket
absence does not authorize retirement or an uncertain effect retry.

## Libcurl and carrier decision

Pinned [libcurl 8.22 socket receive](https://raw.githubusercontent.com/curl/curl/curl-8_22_0/lib/cf-socket.c)
uses `sread`; the pinned
[definition](https://raw.githubusercontent.com/curl/curl/curl-8_22_0/lib/curl_setup.h)
uses ordinary `recv`, without ancillary output. Current `curl_ws_recv` therefore
cannot prove each native control writer. Open/close socket callbacks can make
descriptor ownership explicit, but do not add ancillary-aware receive.
The documented [preconnected socket pattern](https://curl.se/libcurl/c/CURLOPT_OPENSOCKETFUNCTION.html)
can verify an OS connection before HTTP upgrade, and a
[pre-request callback](https://curl.se/libcurl/c/CURLOPT_PREREQFUNCTION.html)
can refuse before request transmission. Neither solves later writer attribution.
Do not patch/interpose ambient libc or let raw receive race with libcurl's reader.

Root must choose a reviewed credential-aware raw stream under WebSocket on both
sides, or a separate bounded owner-control Unix carrier. The latter can share
the same process's real native producer and existing JSON contract without
pretending today's WebSocket reader is reuse/delegation proof. Until a complete
carrier preserves per-segment evidence, owner admission through the current
libcurl-only native channel must remain closed. Existing observational discovery
must retain its narrower user/path scope.

`transport.zig` already has a multi-handle owner thread. Native probing owns each
easy handle synchronously but currently initializes/cleans global curl state per
connection. The provider client initializes global state and does not visibly
balance it in its destructor. The pinned
[global lifecycle](https://raw.githubusercontent.com/curl/curl/curl-8_22_0/lib/easy.c)
is reference-counted, with thread safety conditional on its compiled feature.
Use one explicit process curl lifetime or balanced reviewed leases, initialized
before concurrent use and cleaned only after all easy/multi users stop. Each
easy/multi handle still has one owner. Adding a peer bridge must not close a
descriptor still owned by curl, share an easy handle concurrently, or perform
blocking native callbacks while holding the actor's request/mutation boundary.

## Actual owned-process proof required

Only root may run these through declared locked Nix/Bazel. R-N11 permits bounded
fixture children owned by the test invocation, isolated private roots, explicit
deadlines and cleanup/reaping of those children. No signaling other sessions,
global PID/sysctl changes, host services or personal-vault/provider activity is
needed. A C fixture should fork before application worker threads or spawn a
declared helper executable; do not fork a live threaded daemon into unsafe libc
state. Record exact kernel/closure, fresh execution and refusal scope.

1. One real native fixture process serves control and originates adapter ingress;
   capture both directions and prove equal stable identity. A second real process
   loading the same thread ID must remain distinct. Same-process threads remain
   compatible because the first profile is process, not thread identity.
2. Reconnect to the same still-live process and restart only the owned daemon;
   newly captured pidfds must match original witness plus protocol generations.
   Restart cannot restore authority from a serialized fd/PID or phase alone.
3. Exit original A while retaining its pidfd, then start B and replace the same
   socket path. B must not satisfy A's witness, nonce or generation. A real forced
   numeric-PID-reuse case needs a separate bounded private-namespace fixture; do
   not label ordinary replacement as forced PID-reuse proof.
4. A child writes via an inherited connected descriptor, and an unrelated owned
   process writes via an explicitly transferred descriptor. Reject their first
   segment, including a frame split between original and delegated writers, on
   both control replies and adapter requests. Test a listener created by A but
   accepted/written by B; socket-origin checks alone must not pass it.
5. Exercise missing/truncated/duplicate ancillary, unexpected rights, negative
   pidfd, departure, cancellation and descriptor exhaustion. Verify bounded
   cleanup and no decoded owner request/effect on refusal. Test unsupported
   kernel/namespace permissions as explicit refusals, not simulated positives.
6. Where an owned namespace fixture is permitted, test PID/user namespace mismatch
   and invisible peers. If namespace creation is unavailable, report that positive
   namespace adversarial gate unrun while keeping production refusal intact.
7. Exercise same-thread independent owners, stale ACKs and actor admission with
   actual accepted peer context. Fabricated structs/JSON PIDs supplement validation
   tests but cannot substitute for socket-backed proof.

These proposed cases are unrun. Descriptor tests, protocol fixtures and an
isolated installed Linux checkpoint establish only their recorded predicates;
they never establish stock/native hook availability, provider handoff or Darwin
support.

## Released implementation boundary

Root subsequently selected a separate bounded Unix `SOCK_SEQPACKET` owner
carrier with a 64 KiB packet ceiling and released only
`src/platform/native_peer.c`, its header, `peer.zig` and new peer fixtures to this
worker. Root owns shared BUILD and daemon/native-probe wiring and all execution.
The bridge retains a socket-origin pidfd, verifies each packet or stream segment
against current-writer ancillary evidence, and returns closed error categories.
Capture borrows the socket; duplicate owns independent socket/pidfd descriptors
for queued actor lifetime, with no second reader permitted. Neither the source
release nor independent bridge review establishes daemon integration or a
passing installed-kernel gate.

The C fixture creates/listens in each actual owned producing child and exercises
bidirectional packets, fresh capture of the same live process, inherited and
explicitly transferred writer rejection, mixed-writer stream boundaries,
unexpected rights, payload truncation, descriptor counts on refusal, departure,
distinct process identities and duplicate descriptor lifetime. It does not yet
force numeric PID reuse, change namespaces, restart the daemon, or prove actual
actor retirement/materialization isolation. Those broader gates retain their
unrun scope. No standalone executable or test was invoked by this worker.

## Fresh root-owned bridge proof

Root reports invocation `cf80bcba-4f10-4f1e-8b72-edeb1d87c1e5` passed
`//:native_peer_bridge_test` (0.2 seconds) and `//:native_peer_test`
(0.1 seconds), both freshly executed with zero skipped tests. This exercises
the C fixture's actual owned-process bidirectional evidence, delegated writers,
mixed-writer stream boundaries, ancillary refusal/descriptor cleanup and retained
context lifetime, plus the Zig wrapper's stated witness predicates. Successful
bridge operations establish that the tested kernel exposes the required APIs in
that execution context; source headers alone did not establish this. These short
bounded tests are not measured availability or SLO evidence.

This receipt does not prove current daemon ingress, Rust producer integration,
forced numeric PID reuse, namespace adversaries, daemon recovery, installed owner
lifecycle, Darwin or live same-process continuity. Subsequent shared integration
edits require their own matching-input gates. Canonical C bridge/header bytes are
frozen for producer integration; any mirror must use declared source custody and
receive fresh validation if those bytes change.

Read-only review of current daemon integration finds adapter peer capture,
per-segment verified framing, partial-frame discard on authentication fault and
actor-owned duplicate context propagation. Actor duplication retains descriptors
for evidence only and must not introduce a second socket reader. The current
initial listener called `UnixAddress.listen` before enabling peer options; the
locked Zig implementation performs socket, bind and listen without an option
hook. Root replaced the adapter path with `listenAdapter`: socket, nonblocking,
credential options, bind and listen, followed by private socket mode under the
already private runtime directory. Accepted peer capture still precedes protocol
bytes. This fixes the reviewed ordering at source level; the changed daemon
integration still needs its own fresh declared gate. A successful bind followed
by failed listen also needs exact owned-path cleanup, because that helper's
failure precedes the outer initialized-server count.
Control/browser metadata paths retain their existing narrower user boundary;
unsupported platforms still refuse protected owner admission.

## Declared Codex header portability correction

Root's graph review found the official Codex LLVM toolchain preserves GNU 2.28
with Linux 4.19.325 headers. Its hermetic default lacks `sys/pidfd.h` and the
modern peer constants; importing that unused libc wrapper header hard-failed
before a closed unsupported branch could compile. Root ratified a separate
`owner-linux` profile preserving GNU 2.28 while declaring pinned Linux 6.17.13
UAPI. This is build-header custody, never an installed-kernel inference.

Primary pinned Linux 6.17.13 definitions are
[`SO_PASSPIDFD=76` and `SO_PEERPIDFD=77`](https://raw.githubusercontent.com/gregkh/linux/v6.17.13/include/uapi/asm-generic/socket.h),
[`SCM_PIDFD=0x04`, a read-only integer descriptor](https://raw.githubusercontent.com/gregkh/linux/v6.17.13/include/linux/socket.h),
[`PID_FS_MAGIC=0x50494446`](https://raw.githubusercontent.com/gregkh/linux/v6.17.13/include/uapi/linux/magic.h),
and [`PIDFD_GET_PID_NAMESPACE=_IO(0xFF,5)` / `PIDFD_GET_USER_NAMESPACE=_IO(0xFF,9)`](https://raw.githubusercontent.com/gregkh/linux/v6.17.13/include/uapi/linux/pidfd.h).
[glibc 2.28 socket headers](https://raw.githubusercontent.com/bminor/glibc/glibc-2.28/sysdeps/unix/sysv/linux/bits/socket.h)
import `asm/socket.h`, so the declared modern UAPI supplies socket options; its
ancillary enum supplies rights/credentials but lacks `SCM_PIDFD`.

The canonical bridge now conditionally imports `linux/pidfd.h` with
`__has_include`, rather than using libc pidfd wrappers. It defines only the
missing `SCM_PIDFD=0x04` spelling, guarded by recognition of the actual modern
socket, pidfs and namespace UAPI. Old headers retain unsupported closed stubs;
no replacement PID lookup, UID-only authority or runtime feature relaxation is
introduced. The interface and receive/capture predicates are unchanged.

The kernel pidfd header imports fcntl definitions. Its
[official `HAVE_ARCH_STRUCT_FLOCK` guard](https://raw.githubusercontent.com/gregkh/linux/v6.17.13/include/uapi/asm-generic/fcntl.h)
avoids duplicating the already declared libc flock structures, which this bridge
does not use. Overlapping
[kernel fcntl macro spellings](https://raw.githubusercontent.com/gregkh/linux/v6.17.13/include/uapi/linux/fcntl.h)
are scoped with [push/pop macro pragmas](https://gcc.gnu.org/onlinedocs/gcc/Push_002fPop-Macro-Pragmas.html):
the libc definitions are restored after UAPI import, without suppressing
compiler diagnostics or the modern peer feature checks. This also avoids
numeric-equivalent macro redefinitions becoming warnings-as-errors. Root's
declared compiler checks must verify both the Omux modern-libc graph and the
explicit Codex GNU 2.28/6.17.13-UAPI graph.

Bridge source is frozen after this necessary portability correction. The prior
`cf80bcba-4f10-4f1e-8b72-edeb1d87c1e5` positive peer receipt belongs to the
earlier bridge bytes; the changed bytes need fresh root-owned checks. Clients
must copy the exact canonical modified C/header into a new candidate under
declared custody, rather than changing an older proof epoch in place.

Root's subsequent pinned LLVM 22 / GNU 2.28 / Linux 6.17.13 compile invocation
`980d222c` failed before tests with a duplicate `struct f_owner_ex` declaration.
The kernel's flock guard does not cover that structure: the
[pinned kernel header](https://raw.githubusercontent.com/gregkh/linux/v6.17.13/include/uapi/asm-generic/fcntl.h)
declares its tag unconditionally, while
[glibc 2.28](https://raw.githubusercontent.com/bminor/glibc/glibc-2.28/sysdeps/unix/sysv/linux/bits/fcntl-linux.h)
already declares its own GNU structure. The canonical bridge now scopes a
macro rename of the unused kernel tag to `omux_unused_kernel_f_owner_ex` only
during the pidfd UAPI inclusion, then restores the prior macro state. Libc's
declaration remains intact. This does not disable diagnostics, alter public
bridge types or weaken any runtime feature predicate.

The corrected canonical C source and this note are frozen for exact candidate
copy. Both declared compiler profiles still require fresh root-owned checks;
neither the failed `980d222c` compile nor the earlier positive bridge receipt
proves these revised bytes. No executable or host action was performed by this
worker for this correction.
