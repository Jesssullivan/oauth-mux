Actor | Codex registry/Omux-owned private installation | select installed local
bytes and preserve custody across setup/removal/restoration |
R-HOOK-CONVERGENCE-20261004, R-N12/R-N13, repository AGENTS.md |
original artifact acquire unavailable, no actor selection field |
separate bounded measured selection and revisioned authenticated actor metadata
record in SQLite. The snapshot JSON is stored as TEXT, not encrypted as a whole;
grant payloads remain ciphertext. No secret field is added by this measurement.

This is supporting candidate implementation. The installed receipt is at
`codex-installed-runtime.json`; its profile labels and input receipt references
are observed data. The selection does not verify original archives, source
producer receipts, ELF lookup edges, launch form, executable incarnation,
native history, same-process handoff or provider permission.

The daemon's immutable launch selector `OMUX_CODEX_INSTALL_ROOT` names an
existing user-owned 0700 root. It is not a digest/provenance authority.
Neither RPC nor a peer can supply selection digests, records or descriptors.
Configured Codex installation and setup refresh schedule one bounded job on the
existing native I/O supervisor. The worker owns the root, receipt and member
descriptors while it hashes the complete declared membership twice. Receipt
size, membership, total payload, file sizes and operation time have hard bounds.
The actor rewalks the configured root and every member, checks held descriptor
metadata, and commits a digest it computes itself in authenticated snapshot
metadata. Storage binds this JSON to SQLite as TEXT; encrypted grant payloads
retain their independent custody contract.
The record binds channel, original registry transaction, capability, adapter
epoch and first committed revision. A replacement root or changed member,
snapshot revision, channel, epoch or registry refuses the selection.

Setup/recovery refuses registry drift before native configuration effects.
Removal checks exact selection ownership before detachment and again before
configuration removal, then clears only that actor-owned selection.
Authenticated startup and rollback restore historical selection facts; absence
does not migrate a record or imply readiness. Outstanding worker jobs participate
in shutdown and cannot revive a removed epoch. Selection errors are redacted
metadata in integration status and do not clear native owner/session history.
No credential path consumes this measurement, `native_support` stays false,
and `runtime_selection_producer.acquire` remains fail closed.

The added synthetic tests cover arbitrary non-ELF observations, owned FD
lifetime, actor revision/channel/epoch fences, false support claims, removal
ownership, changed CA bytes, published root replacement, pending removal and
expired deadlines. Build, formatting, tests and installation execution were not
run by the artifact author. After independent source review, the root executor
must apply and validate through the locked Nix/Bazel graph, including actor
install/setup/removal/restart/rollback and capacity/fault suites.

Full native artifact authority still needs an independently selected immutable
deployment input/action/output digest seed from the trusted Omux package/catalog.
Observed installed receipts cannot supply that seed. This slice does not close
the retained native proof or Yoga gates, and does not change runtime009.
