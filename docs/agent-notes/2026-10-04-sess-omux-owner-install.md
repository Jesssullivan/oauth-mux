# Native owner, route and reversible installation review

R-N13 records this review and documentation mutation for the user-selected
native-owner/Codex-protocol sprint. This note proposes implementation; no runtime
source, test, host, service, provider or tracker action was performed. Root owns
the execution queue and authority classification. PZM remains held. The
[owner proposal](../plans/omux-native-owner-custody-next-stage-2026-10-04.md)
and [native reset](../plans/omux-native-account-lifecycle-reset-2026-10-02.md)
supply the outcome and preservation requirements; this review grants no support
or live-continuity claim.

## Inspected behavior and gaps

[Binding and Lease](../../src/domain.zig) retain account/grant/route identity,
but no native owner identity. `State.bind` compares application/session and
refuses replacement while in flight. `beginLease` checks the binding's grant and
route generation; restoration recomputes in-flight counts from leases. Route
bindings arise during acquire, so an attached thread which never acquired has no
route record for removal to discover.

[Engine](../../src/engine.zig) currently releases Codex bindings by application
and thread ID. Its removal check compares those thread IDs with one endpoint's
loaded list. Two native processes loading the same thread can therefore not be
distinguished by these records. Compatible-hook discovery and an idle thread
are necessary checks, but neither establishes a durable exact owner.

[Setup](../../src/integrations/setup.zig) already retains encrypted before/after
configuration, checks capability generation before restoration, preserves
independent edits, uses owned no-follow paths and bounds deadlines. Its result
preflight counts actual JSON after parsed-value serialization against the
mutation result limit. Both `changed` outcomes are checked. The engine calls
removal preflight before detach. These predicates must remain.

`setup.recover` and `setup.install` can also complete `pending_remove` directly.
Owner-aware removal must gate those entrypoints as well as `Engine.uninstall`.
The actor currently authenticates adapter requests against installed/current
shared capability generation. Rotating that generation can otherwise remove
terminal-report authority even when an expired domain lease left an unknown
request attempt. Domain in-flight count alone cannot authorize retirement.

## Coordinated bounded types

Authority owns one shared native reference type; lifecycle and this domain
review agree on its meaning. The internal shape is:

```zig
pub const NativeRef = struct {
    owner_id: [32]u8,
    adapter_epoch: u64,
    endpoint_generation: u64,
    thread_instance_generation: u64,
    attachment_generation: u64,
};
```

All generations are nonzero and overflow refuses. Owner handles use the
64-character opaque hex representation on the control/wire boundary; the actual
internal array serializer must be counted when admitting persisted records.
Application and native thread ID remain separately bounded by their declared
contracts. Owner records retain the verified OS witness and native nonce;
incoming JSON references, PIDs, paths or nonce assertions confer no authority.
Private peer/witness data never enters installation results.

Proposed owner-ledger ceilings are 256 lifetime owner records and 4,096 lifetime
attachment/retirement records. An attachment retains terminal retirement in its
same stable record. Live, pending, unresolved and retired records all consume
capacity; there is no extra unlimited tombstone list or TTL eviction. These
ceilings remain review/ratification choices, not current capacities. Existing
domain lists remain bounded at 1,024 records, source associations at 64, and the
whole persisted envelope at 16 MiB. Shared admission needs explicit owner-list
ceilings rather than applying the domain's 1,024 ceiling to every new list.

Add `native_ref: ?NativeRef = null` to domain Binding and Lease, and to the
request ledger's immutable Intent. Null denotes explicit ownerless legacy or a
non-native adapter; it cannot authorize the new native hook. Domain validates
reference shape and exact Binding/Lease equality. Engine validates linkage to
the independently verified owner/attachment ledger and its phase. Restored
unverified owners may retain leases and report fences without becoming eligible
for acquire or materialization.

Binding identity includes owner, application, native thread ID, thread-instance
generation and attachment generation. Domain replacement must preserve that
native reference; account/grant changes increment only `route_generation`.
Release targets the exact reference and refuses while its leases remain. The
request key stays exactly `(application, native session, original request_id)`.
Changing owner or attachment is an intent mismatch, never a fresh work namespace
or another alternate-attempt budget.

The owner ledger, not the account route, records `pending_registration`,
`attached`, `pending_detach`, `unresolved` and `detached` phases with stable
original operation, exact generations and held outcome credit. This includes
never-acquired attachments. A pending or lost registration reply remains
custody even if no route was created. Forget may remove account routes after its
existing lease checks; it cannot erase this independent native attachment or
prove native detach.

## Removal and installation fences

Before native effects, count complete possible result objects and the complete
persisted candidate, including pending records, credit metadata, retirement and
maintenance growth. Commit the original removal operation, adapter-epoch fence
and obligations first. That fence refuses registration, attachment, acquire and
materialization; it retains exact-owner scoped terminal reports and their
existing request/report credits. Compatible native idle/context/ancillary checks
remain mandatory.

Enumerate all retained attachments for the adapter epoch, including unresolved
registration and never-acquired threads. Each detach uses the original verified
owner/endpoint and exact attachment generation. Persist each matching safe ACK
and retirement before proceeding. An unreachable endpoint, replacement peer,
wrong generation, unknown native state or lost ACK leaves removal pending.
Successfully detached siblings stay retired; another owner's route is unchanged.
No bulk release by thread ID or application is allowed.

Restore configuration and revoke the shared capability only when every required
attachment is safely retired and every request/report obligation is settled,
or when a separately reviewed old-generation terminal-report authority remains.
The first implementation should retain configuration/capability while such an
obligation remains rather than invent that additional credential contract.
Increment adapter epoch only after committed final removal. Reinstall during a
pending removal refuses; explicit reattachment uses a new generation after
removal, and cannot revive retired work.

Proposed setup authorization is a typed internal removal permit binding adapter
epoch, original removal-operation digest, exact encrypted registry transaction
and completion-witness digest to the current capability generation. It is not
a boolean supplied through RPC. Authority/vault must define its seal and verify
it before `remove`, `recover` or install's pending-remove completion can restore
configuration. Legacy pending-remove custody without that reviewed authority
remains pending; absence of a present socket is insufficient. Recovery may
retain/read custody without redispatching an uncertain native effect.

Use a typed bounded pending result: removed=false, installed=true,
pending_safe_detach=true, adapter enum, original removal-operation handle,
adapter epoch, bounded pending count and finite reason enum. No private endpoint
or owner arrays are included. Success keeps existing configuration-path results.
Preflight all actual pending/success JSON variants with the locked serializer
before the first detach, and repeat success checks at setup's locked write
boundary. Reason enums and counts have derived maximum encoded widths; no
unbounded diagnostic or guessed small byte credit is used.

Domain `acquisitionGrowth` must count complete Binding/Lease records carrying
the exact NativeRef and maximum generation widths. Maintenance counts their new
scalar width ranges. Owner/attachment admission counts actual records and
derived possible outcomes, with explicit per-list cardinality credits, inside
the existing whole-envelope check. Committed growth spends only its original
credit; restart and partial detach retain unspent obligations.

## Change and proof proposal

| Owner | Proposed source boundary |
| --- | --- |
| Authority | Shared NativeRef, owner/attachment/removal ledger, immutable request Intent constraint and owner-list admission counts. |
| Lifecycle | Actor staging, peer linkage, work/lease/materialization/report checks, per-owner continuations and whole-envelope credit consumption. |
| Domain/install worker, only after release | `src/domain.zig` exact reference checks and growth; `src/integrations/setup.zig` permit-gated restoration/recovery and complete result preflight. |
| Native/Codex workers | Real versioned registration/ACK producer, OS peer proof, same-incarnation connection handling and unchanged logical-request identity. |
| Vault | Sealed metadata/recovery witness and explicit versioned migration. Self-consistent mutable JSON cannot invent verified owner authority. |
| Root | Shared BUILD/declaration changes, classification and all locked Nix/Bazel batches. |

Required meaningful gates before support evaluation:

1. Two actual private native endpoints load the same thread ID; acquisition,
   materialization and exact-owner detach of A preserve B's route and generation.
2. Attach before any acquire; lost reply and restart retain pending owner,
   original operation and credit. Removal cannot overlook that attachment.
3. Hold registration/acquire at the persisted removal fence. Later admission
   refuses; exact existing terminal reports still commit without another attempt.
4. Detach one sibling, then lose/mismatch the next ACK. Configuration, capability
   epoch and remaining custody stay pending; the first retirement stays durable.
5. Crash at admission/effect/ACK/commit boundaries and repeat startup. No uncertain
   registration/detach/model request is redispatched, and no fresh work key appears.
6. Restore an old pending-remove registry after reinstall, or invoke setup recovery
   with no/mismatched completion permit. Preserve current configuration and
   capability. Exercise install's pending-remove branch as well as `remove`.
7. Actual maximum escaping and generation widths hit the real whole-snapshot,
   owner-slot and cached-result boundaries. Refuse before native/config effects;
   accepted completion spends its held credit without releasing another owner's.
8. Legacy ownerless bindings, modified owner JSON/seal, unknown schema and
   overcommitted obligations refuse migration without changing original
   ciphertext, request keys, attempts, history, registry or checkpoint authority.

The isolated Linux installed checkpoint remains the carried Sting recipe with a
fresh frozen source/archive identity, disposable genuine Secret Service,
production daemon/CLI, offscreen Qt and owned cleanup. It proves those installed
predicates separately. Protocol fixtures, an owner schema or compilation do not
prove stock-native support, ordinary-launch same-process handoff, interactive
desktop/services or provider continuity. All proposed runtime changes remain
unimplemented at that initial review epoch, pending root's explicit source
release and coordinated contract. Subsequent implementation and actual receipts
belong to the [native owner evidence](../implementation/native-owner-evidence-2026-10-04.md).

## Current-source installed checkpoint preparation

R-N13: root retains the existing isolated Sting checkpoint. Its current graph
recipe is `//tools:deployed_fixture --host sting --recipe linux-installed
--source-archive <fresh immutable public-source archive> --timeout 1800`, invoked
only through the locked Nix/Bazel environment by root. The helper supplies the
declared SSH executable and stages only its newly owned private proof workspace.
`tools/host_proof.py` is absent; the implemented entrypoints are
[`host_probe.py`](../../tools/host_probe.py),
[`deployed_fixture.py`](../../tools/deployed_fixture.py) and
[`host_graph.py`](../../tools/host_graph.py). The sole remote graph command runs
`//delivery:installed_custody_test` with `--jobs=4` and the validated proof UUID
as its explicit Bazel invocation ID. The remote Nix bootstrap retains its
minimal environment and explicit `--option eval-cache false` policy.

[`test_installed_custody.py`](../../delivery/test_installed_custody.py) installs
the declared portable archive in a private prefix, starts its actual daemon and
CLI against a disposable real D-Bus/GNOME Secret Service, connects offscreen Qt,
checks durable restart and mutation deduplication, rejects a restored older
database, and ownership-uninstalls only the installed files. Private XDG
directories and the disposable bus isolate custody. No provider account, source,
personal vault, native application store, host service activation or additional
host operation enters this checkpoint. The source/runtime archive hashes and
sizes, proof and orchestration IDs, private log hash, bounded platform/kernel
metadata and both successful cleanup readbacks must belong to the new run.

The historical Sting proof `c6f3600c-a728-490b-8219-ee4158f6f179` retains only its
frozen `7268df4b...` source and `aed5dce3...` runtime scope. Its workspace was
removed. The new owner/schema runtime needs fresh local gates, frozen source,
runtime artifact and isolated installed receipts. Read-only inspection found a
fixture baseline requiring SQL `user_version=2`, while fresh current storage
creates schema 3. Root authorized a narrow fixture correction: the current
declared test now requires exactly schema 3 and checks the owned 152-byte
`OMUXR002` authority record's lineage, sequence, nonce, revision and SHA256
against the actual SQLite checkpoint and exact stored metadata bytes after both
daemon shutdowns. This structural inspection reads no vault key and does not
authenticate or synthesize the MAC; genuine production startup retains that
responsibility. The correction is written and awaiting root's declared gate.
The historical schema-2 receipt stays unchanged.

R-N13: later installed-fixture feedback identified `StoreBusy` at daemon
restart. Python's SQLite transaction context does not close its connection,
so the fixture retained an inspection reader across exclusive daemon startup.
Both owned inspection connections now use `contextlib.closing`, releasing
their readers before daemon restart or database rollback replacement. The
production exclusive locking and zero busy timeout remain unchanged. Root owns
the fresh installed target and subsequent Sting checkpoint; this correction
has no execution receipt yet.

## Optional future native process integration gap

R-N13: native protocol proof remains separate from the installed daemon proof.
The current experimental Codex source starts a same-process owner endpoint in
ordinary app-server and embedded startup, with an actual profile self-exchange
before publication. It places that endpoint at a newly owned
`CODEX_HOME/omux-owner-<opaque-prefix>/owner.sock`. Source inspection and direct
Engine/packet fixtures do not prove that a compiled ordinary application process
can install, late-attach and detach against the installed portable daemon.

A later bounded extension would need the exact newly compiled experimental
Codex executable and its source/patch/compiler receipts as declared graph data,
plus a reviewed no-provider ordinary-startup/thread recipe. The Omux module
currently declares no such Codex executable input. A dedicated declared harness
could then use a short private `CODEX_HOME`, sanitized environment, the same
disposable vault, real native thread publication and the production owner
packet/control paths. It would verify one-time install, pre-first-acquire
registration, exact attach/detach acknowledgment, pending removal on an actual
unreachable owned producer, unchanged native thread/store and config/capability
custody, and cleanup of only its owned processes and paths. It must exclude
provider/model calls and personal resources by construction; default startup
network/plugin behavior needs review before that recipe is executable.

Sting's historical numeric kernel 6.12.0 is not runtime peer-profile evidence.
The reviewed upstream API floor is Linux 6.11, and actual pidfs, namespace and
per-packet checks must still pass on the exact execution host without fallback
or a synthetic witness. A future successful no-provider app-server checkpoint
would prove those process/custody predicates only. Stock Codex/TUI support,
account handoff, accepted-stream continuity, provider authorization and seamless
native history/tool/approval preservation remain distinct unrun live gates.
No new native probe, production change or host call was made for this
preparation. Only the authorized installed-fixture baseline/structural checks
and this note changed in the installed preparation lane.

## Actor removal gate feedback

R-N13: root's coordinated full-suite report established the actual
never-acquired-owner case's exact detach acknowledgment, configuration
restoration and retirement predicates. The other three new removal cases
reached the actor installation refusal but expected the lower-level setup
error. The actor's persisted application-removal fence correctly returns
`NativeRemovalPending` before setup's permit boundary. The narrowly corrected
actor installation expectation now names that exact error; lower-level setup
and unresolved recovery expectations remain `NativeCustodyPending`. Exact
configuration/capability/encrypted-registry comparisons, original operations,
held credits, restart and no-redispatch checks remain intact. The correction
awaits root's next declared gate; the three cases do not inherit a pass from
the successful removal case or from this source review.
