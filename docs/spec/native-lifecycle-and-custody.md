# Native lifecycle and custody contract

Status: active subordinate specification for the **experimental, unshipped**
[native reset](../plans/omux-native-account-lifecycle-reset-2026-10-02.md).
This contract does not enlarge a release claim. Implementation and recorded local
predicates are described in the [evidence record](../implementation/native-reset-evidence-2026-10-02.md).
Acceptance IDs below name requirements, not completed gates.

## Authority and state

The resident per-user daemon owns lifecycle and grant custody. Thin-client exit
does not stop it. Supervised adapters own native protocol boundaries; neither
an adapter declaration nor a mock binding establishes native attachment.

| Entity | Authority |
| --- | --- |
| Identity | Independently verified provider, issuer, subject and tenant; labels and copied native hints cannot establish identity |
| Account | Identity plus account type, preferences and admission lifecycle |
| Source | Explicit authorization to acquire from a particular native store, input or browser context, including expiry |
| Grant | Credential form, audience, scopes, purposes, generation, provider/custody expiry and renewal owner |
| Observation | Typed value, resource, unit, window, bucket, provenance and freshness |
| Binding | Native application/session authority and sticky account route |
| Lease | Bounded purpose-specific use, fenced by grant and route generations |

These are independent records in `src/domain.zig`. A valid credential does not
prove entitlement or remaining capacity. Source authorization does not prove
provider validity. Passwords, OTPs, passkeys and security keys are enrollment
factors, never interchangeable grants. Browser read permission is not API-call
permission. Unknown or stale observations cannot become invented readiness.

## Enrollment and provenance

Only an authorized, connected, unexpired source may enroll. Acquisition reads
only the declared private file or browser fields. Native file ownership,
permissions, no-follow traversal and stable reads precede import. A copied
identity claim remains a candidate until a fixed provider identity reader verifies
it independently. Verified identity determines deduplication across sources;
conflicting or unverified imports quarantine rather than activate an account.

Imported access credentials remain externally owned. Import cannot adopt refresh
authority. Retain source context and verification provenance privately; expose
opaque account/source/grant handles and redacted status to clients. The current
engine independently verifies GitHub/Codex candidates and hashes public account
handles. A declared endpoint and fixture response do not prove live provider
semantics for an application/version.

Manual API-key imports currently default to 30 days of custody; copied native
and manual OAuth imports default to one hour. Explicit custody is bounded to
one second through 30 days and cannot extend a known provider expiry. Expiry is
checked again at admission and materialization, not only on initial import.

## Separate lifecycle operations

| Operation | Required effect | Current implementation boundary |
| --- | --- | --- |
| Detach | Record source disappearance; retain account history and independently valid grants | `detachSource`; discovery reconciliation distinguishes missing source from credential invalidity |
| Disconnect | End that source's acquisition authority and admission through its grants | `disconnectSource` invalidates source grants; engine source/browser disconnect deletes their ciphertext |
| Pause | Prevent new account admission without upstream revocation | Account lifecycle becomes `paused`; held work remains governed by its lease |
| Drain | Prevent new leases while existing bindings/work finish | `draining` plus in-flight route/lease checks |
| Forget | Remove retained account secrets and account runtime records; leave a re-enrollment tombstone | Refuses in-flight leases; engine atomically persists domain removal with storage tombstone/deletion |
| Explicit re-enrollment | Clear matching identity tombstones only after explicit intent and renewed authorized verification | Domain authorization checks plus engine verified import path; periodic reconciliation cannot clear tombstones |
| Upstream revoke | Explicitly ask provider to revoke and report actual result separately from local removal | Provider revocation execution remains a gap; a job enum is not implementation |

Identity tombstones block automatic enrollment from a newly named source too.
Storage also retains account tombstones and generation history so deletion and
reimport cannot resurrect an old lease. Forget removes account, grant,
observation, binding and account-job records; it does not erase the authorized
source itself or imply deletion of provider/native session stores.

Deleting current ciphertext is not a claim of forensic erasure of old encrypted
WAL pages or separately retained backups. A separate authenticated installation checkpoint fences SQLite-only restore:
older databases cannot resurrect forget or rotation authority. This protection
does not establish safety against coordinated rollback of both the database and
its independent authority, vault loss, or forensic erasure. Existing version-1
databases require explicit migration and fail closed; automatic migration cannot
bless an older backup as current authority. Backup retention must
preserve that authority; key destruction and upstream revoke are separate
operations with separate evidence.

## Persistent custody and renewal

SQLite metadata and authenticated encrypted grant payloads have one writer.
`src/envelope.zig` uses XChaCha20-Poly1305 with secure random nonces and
length-delimited associated data binding the envelope format, wrapping-key ID,
account, grant, generation, purpose and scope. Seal before SQLite insertion so
database, WAL and backups never receive grant plaintext. Owned decrypted buffers
must be scrubbed on success and failure; key and secret bytes never enter argv,
logs, diagnostics or evidence.

The wrapping key resides in macOS Keychain or Linux Secret Service through the
native bridge. An existing database supplies its recorded root ID. Missing,
locked, denied, malformed or unavailable key custody fails closed; startup never
creates a replacement over an existing database, and no plaintext fallback is
permitted. Fake-backend and negative ABI tests are local predicates. Genuine
isolated Linux Secret Service roundtrip, reopen, create-conflict, malformed-key
and deletion checks passed in the [safety evidence](../implementation/native-safety-evidence-2026-10-03.md).
A genuine private macOS Keychain driver also passed against the locked SDK.
Personal-session custody, production Darwin runtime and service behavior
require separate receipts.

When wrapping-key IO fails with a typed OS-vault error, credential-free local
controls remain available. `Locked` retains its existing wire status/refusals;
other vault failures report `vault_unavailable` and an exact redacted
`custody_error`. Missing/invalid original keys require original-key restoration;
denied/cancelled/unavailable access requires normal platform-access restoration.
These retained diagnoses do not establish the current OS-vault state or permanent
key loss. Database, corruption, allocation and other non-vault errors remain
startup failures; error names alone cannot grant vault provenance.
After normal platform-vault unlock or restoration, the user explicitly calls `custody.reopen`
with no parameters or an empty object. The same daemon actor stages custody and
loads the existing database using its recorded root; failed retry leaves custody
unavailable. This action does not enroll a source or initiate a provider request.
Until loading succeeds, `system.health` reports `metadata_loaded: false` and
`account_count: null`, rather than asserting an empty account store. Its
`vault_locked` status records the retained startup condition; setup vault evidence
is stale diagnostic evidence, not a fresh observation that the OS vault remains
locked. Existing custody retries retain the original database/directory physical
identity and never switch to first key creation if that history disappears or is
replaced. A genuinely fresh initial namespace, checked absent of the database and
recovery siblings, may perform its original first key creation only while that
same namespace and absence still hold at explicit retry. The storage writer
checks that opening expectation before SQLite IO and retains its own exclusive
creation/original-inode witness. Only that owned first creation can transition
the actor to existing custody after a later staging failure; subsequent retries
load the original key and created database. A raced file appearance cannot become
first-install authority. First creation is not a replacement-key or
permanent-loss recovery workflow. Full permanent-key-loss
recovery into separately authorized fresh custody remains unimplemented.
These are source semantics, not an installed normal-vault recovery proof.

Each adopted refresh lineage has exactly one renewal writer. `src/storage.zig`
records rotation intent before issuer contact and allows only the creator of
that intent to issue it. Successful rotation commits successor ciphertext and
snapshot revision together. A replayed pending operation or crashed uncertain
rotation quarantines; it cannot retry or restore a possibly spent token.
Expected generations fence concurrent writers and stale successors. The current
store implements this local transaction machinery; production adoption,
external-writer reconciliation and provider renewal remain unproved integration
work. Imported grants remain external.

## Local channels and leases

Private state directories are owner-only; sockets are mode `0600` and every
connection must match the daemon user's peer UID. Descriptor/no-follow traversal
rejects unsafe owners, permissive directories and symlink aliases. Linux state
uses `XDG_STATE_HOME` or `~/.local/state/omux`; macOS uses
`~/Library/Application Support/Omux`. On Linux, an explicitly supplied `XDG_RUNTIME_DIR` must be an existing safe
owner-only directory; unsafe, missing or empty supplied values fail closed.
Absent runtime configuration uses the state directory's `run/`. A shared
`src/paths.zig` selector places daemon, clients and native setup consistently;
installed platform/service behavior remains a separate conformance gate.

Control receives redacted metadata and cannot materialize credentials. Adapter
authentication additionally requires an installed application capability, derived
for its name, installation ID and epoch. Enrollment capability cannot acquire native
request leases; request authority cannot become general credential export.
Browser messages have a separate bounded schema/channel. Same-user peer checking
is a user boundary, not isolation from a malicious process already controlling
that user's files or capabilities.

Lease creation and materialization recheck purpose, audience, scope, source
authorization, provider/custody expiry, grant generation and route generation.
Changing a route cannot switch in-flight accepted work. A pre-acceptance rejection
may admit a compatible alternate within the bounded attempt budget. Accepted
streams and tool execution are never replayed. A durable request ledger fences at most two attempts for a mandatory opaque
request ID and immutable demand; terminal IDs never expire into reusable authority.
Restart marks unfinished requests unknown and denies replay. Domain in-flight
leases remain until an explicit terminal report; handles whose materialization
capability was lost on restart cannot expose credentials. An unknown request
may report completion only with durably acknowledged acceptance; unknown issued
work without that acknowledgment may only report abandonment. Clock expiry
blocks materialization but never proves native work finished or permits unsafe
forget, detach or route change. Native session state stays authoritative.

## Browser boundary

Chromium/Firefox acquisition requires narrow provider permissions, an exact
extension/native-host authority and a declared origin. Preserve domain, path,
store/container, partition, first-party context, secure/HTTP-only attributes and
expiry for permitted cookies/storage. A capsule cannot expand fields, purpose or
renewal ownership. Browser-bound authorization retains its signing/context
authority and reports browser-required when absent; browser closure alone does
not revoke a genuinely exportable grant.

`src/browser_bridge.zig` rejects unsupported schemas and production cookie/storage
exports pending provider proof. Fixture mode does not authorize production.
Native-host packaging/registration fixtures do not establish installation into a
real browser profile. Browser automation is outside the architecture. Page-reader
drift must disable that reader while preserving independently valid routes.

## Acceptance ledger

Run project checks only through locked Nix inputs and Bazel. This table interprets
the [reset receipts](../implementation/native-reset-evidence-2026-10-02.md) and
[current safety receipts](../implementation/native-safety-evidence-2026-10-03.md);
it is not an independent execution receipt.

| ID | Observable acceptance | Source/local evidence and remaining gate |
| --- | --- | --- |
| LC-01 | Unverified/conflicting identity cannot activate; verified identities deduplicate only within authorized provider sources | Domain/discovery/engine fixture predicates recorded; live fixed-reader identity proof unrun |
| LC-02 | Missing source detaches; explicit disconnect ends source admission; neither action implicitly revokes upstream | Domain/discovery/engine implementation; real native-source disappearance/reappearance unrun |
| LC-03 | Pause/drain deny new admission, allow held completion and refuse unsafe forget/route change | Domain and actor fixture predicates; native same-process execution unrun |
| LC-04 | Forget deletes current secrets and survives restart; renamed sources cannot bypass identity tombstones; only explicit verified re-enrollment clears them | Domain/storage/actor fixtures; SQLite-only stale-restore fences implemented; coordinated rollback and forensic deletion unproved |
| LC-05 | Database, WAL and SQLite backup contain ciphertext; context swaps/tampering fail authentication | Envelope/storage synthetic fixtures recorded; installed Linux wrapping-key and rollback predicates passed, installed grant-write and full-user rollback gates remain distinct |
| LC-06 | Existing database with unavailable/wrong key fails without creating/replacing its root | Vault/storage fake and negative ABI predicates plus genuine isolated Linux and private macOS driver IO recorded; personal-session locked-vault existing-DB recovery and production Darwin runtime remain separate gates |
| LC-07 | At most one issuer renewal attempt per durable operation; uncertain crash quarantines; generation and snapshot advance atomically | Storage fixtures recorded; adoption/provider rotation and external-writer reconciliation unproved |
| LC-08 | Wrong peer/channel/capability/purpose, stale generation and expired lease cannot export authorization | Daemon/domain/engine fixtures recorded; installed native adapter and platform peer conformance unrun |
| LC-09 | Browser origin, exact field scope, context and external renewal owner survive import; production without proof fails closed | Bridge/grant/extension/native-host fixtures recorded; real browser import intentionally blocked |
| LC-10 | Public snapshots and error diagnostics contain only redacted metadata/opaque handles; private buffers are scrubbed | Engine/bridge/envelope fixture predicates; full platform diagnostic/crash audit unproved |
| LC-11 | Per-user path/socket custody resists symlink and ownership substitution; client exit leaves resident daemon | Paths/daemon fixtures and isolated installed Linux daemon/Qt socket proof passed; strict XDG runtime placement and persistent singleton implemented; OS-service lifecycle and Darwin remain unproved |
| LC-12 | Explicit upstream revoke reports actual provider result without silently equating it with forget/disconnect | Required; provider executor and version-bound evidence missing |

Live continuity additionally requires ordinary launch/resume, verified native
attachment where existing-process attachment is claimed, compatible handoff in
the unchanged process and preserved native
history/tools/approvals without routine prompts. These lifecycle predicates alone
cannot establish that product outcome.
