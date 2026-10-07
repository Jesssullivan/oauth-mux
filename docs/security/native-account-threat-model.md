# Native account threat model

Status: active subordinate security model for the experimental, unshipped
[native reset](../plans/omux-native-account-lifecycle-reset-2026-10-02.md).
The historical July security model is not current implementation authority.
The [lifecycle/custody contract](../spec/native-lifecycle-and-custody.md) defines
acceptance IDs. The [reset evidence](../implementation/native-reset-evidence-2026-10-02.md)
and [current safety evidence](../implementation/native-safety-evidence-2026-10-03.md)
record executed predicates and unrun gates. No predecessor proof transfers here.

## Assets and trusted boundaries

Protect grant plaintext, wrapping keys, renewal lineages, source permissions,
verified identity associations, native session/tool/approval authority, route
leases and forget tombstones. Account metadata, provider subjects, source paths,
labels and resource descriptors may be sensitive even without credential bytes.
Private SQLite metadata is not wholly encrypted: grant payload encryption must
not be described as database-wide metadata confidentiality.

The OS user and OS vault form the custody boundary. The daemon's serialized
engine/SQLite writer, envelope implementation, fixed provider readers and narrow
native bridges are trusted for their declared jobs. Supervised adapters receive
only their native purpose authority. Thin clients and browser messages cannot
assert identity or expand grant purpose. The separate documentation SPA is not
runtime authority. External providers determine credential validity and capacity;
an Omux lease cannot extend either.

Adversaries include another local user, an untrusted same-user client without an
adapter capability, hostile browser/page data, forged copied credential metadata,
malformed provider responses, concurrent native refresh writers and crash/replay
conditions. Root or full compromise of the same OS user, kernel, vault service,
trusted adapter or daemon can defeat this boundary. Peer UID and private files do
not provide a separate security principal for every process of the same user.
Cross-host federation, Windows, Safari, arbitrary interception and speculative
accepted-stream recovery are outside this model.

## Threat and control ledger

| ID | Attack or failure | Required control and current boundary | Acceptance |
| --- | --- | --- | --- |
| NC-T01 | Another user connects to local sockets or replaces a private path | Owner-only directories, `0600` sockets, peer UID checks, descriptor/no-follow traversal, strict XDG runtime selection and persistent singleton custody; isolated installed Linux daemon/Qt socket proof passed, service activation and Darwin remain separate gates | LC-08, LC-11 |
| NC-T02 | Same-user control client requests raw tokens or reuses an enrollment capability for request leases | Separate channels/method admission; installation/application/epoch-bound capability; private materialization requires a current purpose-bound lease; same-user capability theft remains outside isolation guarantee | LC-08, LC-10 |
| NC-T03 | Copied label, JWT/native account hint or browser claim enrolls the wrong identity | Authorized source, fixed independent provider reader, issuer/provider checks, verified deduplication and quarantine; live identity-reader semantics unproved | LC-01 |
| NC-T04 | Native file swap, permissive file, symlink or rewrite changes acquisition context | Exact declared file, ownership/mode/no-follow and stable metadata reads; source IO follows authorization; discovery fixtures cover these predicates | LC-01, LC-11 |
| NC-T05 | Database/WAL/backup or row swap discloses or changes authorization | Encrypt before insertion; XChaCha20-Poly1305 authenticates key ID/account/grant/generation/purpose/scope. Independent authenticated installation/sequence/nonce authority reserves mutations before SQL commit and rejects SQLite-only rollback while that authority survives. Plaintext metadata remains protected by OS files; full-user rollback is excluded | LC-05 |
| NC-T06 | Locked/missing vault silently creates a new key over retained ciphertext | Recorded root ID plus typed fail-closed load; no plaintext fallback or key regeneration for existing database. Isolated genuine Linux Secret Service roundtrip/reopen/conflict/malformed/deletion proof passed; Darwin and personal-session access-control behavior remain separate gates | LC-06 |
| NC-T07 | Native/browser import steals renewal ownership or two writers spend one refresh token | Imports retain external ownership; explicit verified adoption required; writer lock and durable rotation intent; provider adoption/external-writer reconciliation still missing | LC-07 |
| NC-T08 | Crash after provider rotation restores/retries a spent predecessor | Pending operations quarantine instead of reissue; atomic successor ciphertext/snapshot commit and idempotent operation IDs; live provider/crash gate unrun | LC-07 |
| NC-T09 | Delayed response, old grant ID or stale lease authorizes a changed route | Durable grant generations, route generations, lease expiry and completion-time authorization checks; generation history survives deletion | LC-04, LC-08 |
| NC-T10 | Source removal destroys valid retained authorization, or reconnect bypasses forget | Detach differs from disconnect; identity tombstones block renamed-source enrollment; explicit verified re-enrollment alone clears them | LC-02, LC-04 |
| NC-T11 | User believes local forget/disconnect revoked upstream or erased every backup | Distinct operations and honest result reporting; current forget removes retained current ciphertext and keeps tombstone, with no provider revoke executor or forensic-backup erasure claim | LC-04, LC-12 |
| NC-T12 | Browser/page expands origin, cookie scope, storage fields, partition or renewal authority | Exact native-host extension authority, narrow permissions, bounded schemas and declared fields; browser-bound grants retain context; production export blocked pending provider proof | LC-09 |
| NC-T13 | Forged/stale usage or quota aliases manufacture aggregate capacity | Typed provenance/freshness/windows/units; verified identity reader; shared buckets counted once; malformed results preserve prior evidence rather than invent readiness | LC-01, LC-08 |
| NC-T14 | Authenticated redirect sends authorization to an attacker or provider JSON exhausts memory | Fixed endpoints, no authenticated redirects, TLS verification, bounded libcurl work/response queues and deadlines; loopback/TLS fixture proof only | LC-01, LC-08 |
| NC-T15 | Handoff replays accepted output/tool execution or changes native session authority | Durable request identity and two-attempt acceptance fence, in-flight route checks, restart uncertainty and native safe-boundary hook. Lease expiry never clears accepted work; terminal authority is explicit. Synthetic actor proof cannot establish live continuity | LC-03, LC-08 |
| NC-T16 | Logs, argv, error bodies, browser parse copies or diagnostics leak credentials/PII | Metadata-only/redacted public views, typed error names, direct OS-vault API, owned secret scrubbing including escaped browser values; comprehensive platform crash/diagnostic audit unproved | LC-10 |
| NC-T17 | Oversized/deep/duplicate frames, slow peers or abandoned streams monopolize daemon work | Bounded parsing/framing/queues and owner-executed deadline/cancellation. Stable mutation IDs and keyed canonical intent retain redacted outcomes across lost replies/restart; uncertain external effects stay indeterminate. Replay ledgers fail closed at bounded capacity rather than evicting authority | LC-08 |

## Security decisions and unresolved gates

The daemon must not silently turn source-read permission into API, refresh or
revocation authority. It must not make a general control credential-export API.
Browser-bound material cannot become a portable bearer grant by changing a type
tag. Quarantine is preferable to retrying an ambiguous refresh lineage. Native
session stores remain in place; a forked home or restarted process is not proof
of preserved authority.

Genuine Linux Secret Service execution and isolated installed production daemon/
Qt socket custody have passing receipts in the current safety evidence. They do
not prove a personal login session, OS-service activation or interactive desktop.
MacOS Keychain and Darwin bundle execution need their own receipts. Linux uses
a validated private `XDG_RUNTIME_DIR` with an installation-specific child; only
an absent variable selects the explicit `state/run` fallback. Empty, missing or
unsafe supplied runtime paths fail closed. A persistent state lock fences
different runtime selections and existing legacy daemon locks.

Production refresh adoption, external-owner coordination and upstream revocation
need implementations and version-bound evaluation. Production browser exports
remain disabled. SQLite-only restore is fenced by the independently retained
authenticated authority. Missing/mismatched authority and legacy schemas are
rejected; there is no automatic recovery migration or restoration merge. A
full-user snapshot restoring both database and authority is outside this model.
Long-lived request/mutation ledger retirement remains a separate design gate.

Metadata-only diagnostics still require a complete audit of native paths, labels,
provider response bodies, stderr and crash artifacts before a platform claim.
Scrubbed heap buffers do not establish protection against privileged memory
inspection, swap or core dumps. No such stronger guarantee is claimed.

For every promoted platform/application, retain exact version/commit provenance,
redacted gate results and missing-hook status. Use artificial nonsecret fixtures
for local checks through locked Nix/Bazel inputs. Never capture real credentials,
raw account IDs, emails or PII screenshots in source, logs or evidence. This
document is a security interpretation of the linked receipts, not an independent
execution receipt or live-provider evaluation.
