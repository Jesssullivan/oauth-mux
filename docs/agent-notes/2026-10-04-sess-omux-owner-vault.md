---
title: Native owner original-witness custody review
date: 2026-10-04
status: review_only_unimplemented
summary: Bind retained owner provenance to exact snapshot bytes and independent installation custody without authorizing uncertain effects.
refs:
  - R-N13
  - R-N11
  - R-N12
---

This R-N13 review supports the user-selected native-owner/Codex protocol and
isolated Linux installed-custody stage. It changes no runtime code and executes
no build, test, host command, vault operation, service or provider request.
Root remains the sole proof coordinator. The preceding admission and Sting P1
receipts retain their exact source/artifact predicates; this proposal inherits
no passing integrity, native-owner, installed or live-continuity gate.

## Observed boundary

`src/recovery.zig` authenticates a fixed installation/sequence/nonce record with
the wrapping key and key identity. `src/storage.zig` compares that record with
the SQLite checkpoint, reserving the next independent checkpoint before SQL
COMMIT. This fences SQLite-only rollback while independent authority survives.
It does not bind the snapshot revision or `metadata_json` bytes to that record.
Grant AEAD independently authenticates its declared envelope context, not all
SQLite metadata or owner provenance. Structural JSON validity, current typed
admission validation and self-consistent ledgers cannot reconstruct historical
verified native peer attribution.

The trusted daemon/writer, OS wrapping-key custody and surviving independent
authority are prerequisites. This review addresses modification/substitution
of retained snapshot authority without those trusted inputs. It does not add
isolation against full compromise of the same OS user, daemon, kernel or vault,
or simultaneous rollback of SQLite and its independent authority.

## Recommended minimal binding

Extend the existing independently authenticated checkpoint record to a new
explicit format containing snapshot revision and a fixed 32-byte SHA-256
commitment to the exact stored `metadata_json` bytes. Authenticate the complete
new payload, including format, installation, sequence, nonce, revision and
digest, using the existing wrapping-key HMAC with a distinct versioned domain
and unambiguous bounded key-identity encoding. Store the matching revision and
commitment with the SQL checkpoint. Do not create a second owner-specific MAC,
another authority file, another vault secret or an automatically rotating key.

The commitment covers the whole existing bounded snapshot because its original
request/mutation fences, attempt history, retirement records, lease/binding
authority and outcome credits constrain native owner authority. An owner-only
projection would leave those dependencies mutable; maintaining a second
serializer and dependency whitelist would create another integrity seam. The
digest is computed from stored bytes, without reparsing/canonicalizing or
allocating a second serialized snapshot. Identical semantic JSON with different
bytes requires a new ordinary commit. This is metadata integrity, not metadata
encryption or a claim that every SQL row is authenticated.

The authority and lifecycle workers confirm that the proposed owner ledger lives
only in the persisted snapshot. The immutable original witness includes the
versioned platform proof profile, opaque owner reference, adapter epoch,
endpoint/thread/attachment generations, native nonce and original operation
intent. Original request identity and attempt history remain in their existing
namespace. A live kernel peer handle remains process-local; a serialized FD or
PID is never recoverable peer authority. Witness fields must be collected by the
verified peer boundary before persistence, rather than accepted from a control
client or reconstructed from mutable labels.

## Commit, opening and crash ordering

The storage writer computes the successor commitment from the final
transactional snapshot and revision. In the same SQLite transaction it writes
the snapshot, original witness/operation/fence/credit and matching checkpoint.
It then durably reserves that exact successor in the independent authority and
commits SQLite, retaining the existing fail-closed publication/COMMIT poisoning.
Native effects may start only after successful commit. Every storage mutation,
including revision-only SQL rotation/quarantine paths, uses this common finish
boundary; initial creation inserts the initial snapshot before deriving and
publishing its sequence-zero commitment. Duplicate read-only outcomes need no
new reservation.

There is no atomic transaction spanning the authority file and SQLite. A crash
before authority publication can roll back the uncommitted SQL transaction. A
crash after publication but before SQL commit leaves an ahead authority and
refuses startup; it never signs the older database, rolls the authority back or
retries an external effect. Failure to prove publication/COMMIT remains poisoned
and requires explicit recovery intervention. Successful SQL commit leaves both
records matching; a crash after a native effect but before its terminal commit
retains unresolved original work and its credit without redispatch.

Opening verifies the supplied wrapping key before trusting retained custody.
After bounded schema/byte checks, verify independent record authentication,
installation/sequence/nonce equality, snapshot revision and exact digest before
typed owner reconciliation or any SQL recovery/authority reservation. Typed
schema, admission-budget and owner-policy validation still independently run
before recovery effects. Missing keys, authority, seal, unknown formats,
checkpoint mismatches, malformed snapshots and unsupported unresolved SQL
obligations fail closed. Existing actor-mode refusal of pending SQL rotation
remains; this seal does not invent a renewal executor or SQL obligation model.

An authenticated snapshot proves that the trusted writer committed particular
original evidence. It does not prove current peer liveness, incarnation equality,
an effect acknowledgment, a correct operation plan or permission to resume.
Restart retains witnesses, work IDs, attempts, generations, tombstones, ciphertext
and credits; attached/pending owners become unverified/unresolved. Reattestation
requires fresh reviewed OS-peer proof matched to the retained original witness.
Until a separate original-witness/acknowledgment protocol is implemented, there
is no automatic registration, detach, materialization or uncertain-work resume.

## Backup, migration, rotation and bounds

SQLite's consistent backup includes snapshot and matching SQL commitment, never
the independent authority. A backup with old checkpoint refuses against newer
surviving authority; current-lineage substitution with changed snapshot bytes
refuses against its authenticated digest. Copying the commitment alongside
changed JSON cannot authenticate it. Missing independent custody is not
permission to initialize, repair or resign an existing database. Ciphertext
before insertion/WAL/backup predicates and grant envelope contexts stay intact.

Storage schema and authority record versions are separate from actor snapshot
schema versions. A legacy authority record does not authenticate its retained
JSON, even if that JSON supplies internally consistent owner rows. The first
native-owner profile must refuse converting legacy/unsealed attribution into
owner authority. A separate explicit migration design may preserve old
ownerless bindings/leases as unresolved while preserving every original work
ID, attempt, mutation, ciphertext and tombstone; it must not infer an original
witness from the current peer, reset a request namespace or sign arbitrary
retained JSON as verified history. No automatic migration or migrator is
authorized by this note. Unknown versions, pending unsupported obligations and
overcommitted migration outcomes refuse before durable custody changes.

This refusal has an explicit compatibility cost: requiring the new record at
daemon startup would hold existing unsealed installations, rather than silently
upgrade them. Root must choose and document the user-visible deployment gate
and a reviewed conversion or explicit new-installation path before shipping.
No automatic reinstall, deletion, reauthorization, plaintext export or fallback
to unsigned owner authority follows. A fresh installation alone does not prove
that conversion of retained history is supported.

The wrapping key remains the existing vault-held installation key. A new HMAC
domain provides format separation; it is not key rotation. Missing/conflicting
key behavior remains unchanged. Actual wrapping-key rotation would need its
own reviewed grant re-encryption, checkpoint resealing, crash and backup design;
this proposal provides no partial rotation or old-key fallback.

The exact JSON ceiling remains 16 MiB. The fixed digest and revision live in the
SQL checkpoint and authority record, so they do not consume serialized snapshot
bytes; proposed owner/witness fields and all outcome credits do consume that
existing envelope and require exact admission plus slot accounting. Hashing is
bounded by the same ceiling and needs constant working space. Owner count,
witness field lengths, supported profiles and retirement capacities remain
ledger design gates. No seal bytes, private witness, key or raw snapshot enter
control views or public evidence.

## Required fresh gates before implementation claims

- Actual same-checkpoint snapshot tampering, including coordinated owner,
  original-work, retirement and credit edits, refuses before recovery effects.
- Revision, digest, format, installation and wrong-key substitutions refuse;
  missing key never regenerates, and legacy owner claims never become verified.
- Real SQLite crash boundaries before/after authority reservation, COMMIT,
  native effect and terminal commit preserve fail-closed custody and no replay.
- Current/old consistent backups preserve ciphertext and reject divergent or
  stale authority; no recovery path automatically reseeds or signs old bytes.
- Exact 16 MiB and owner-slot admission, allocation failure and fixed-record
  bounds preserve old snapshot/credits before effects and avoid extra copies.
- Genuine disposable Linux installed custody proves the changed exact artifact
  under its own fresh receipt. It does not prove services, personal vaults,
  production Darwin, live native continuity or uncertain-effect reconciliation.

Root must review this design and release the single storage/recovery writer
before implementation. All required execution then uses root-coordinated locked
Nix/Bazel. PZM remains held; no host, service, provider or publication authority
is created here.
