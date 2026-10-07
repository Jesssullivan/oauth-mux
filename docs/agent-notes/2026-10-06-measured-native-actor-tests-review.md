# Measured runtime actor test predicates — 2026-10-06

Authority: repository AGENTS.md and the root task's explicit authorization for
a separate test patch while actual inputs remain frozen. Independent source
review: native_selection_review, 2026-10-06; source cleared, execution pending.

The applied `//:measured_runtime_actor_test` uses the existing genuine local
socket producer and ordinary installation RPC. A scoped `builtin.is_test`
constructor captures the exact private fixture installation root before actor
bootstrap. Tiny non-ELF files intentionally qualify as measured local bytes
only. The production acquisition verifier still fails closed and native support
remains false.

Four tests exercise the real Supervisor installation worker and actor commit;
SQLite restart and committed-state restoration; malformed digest, channel and
transaction refusal before ownership transfer or setup effects; rejection of
another selection's removal, then clearing only the owned selection; and a real
carrier's failed publication when the existing snapshot capacity is saturated.
The latter clears only its private fixture selection before attempting the new
commit and claims rollback of that attempted selection, not restoration of an
earlier selected record. It intentionally consumes the finite existing snapshot
limit, approximately 16 MB. Configuration, registry and capability bytes are
compared without printing them and wiped after use.

No build or test was executed by this lane. Root declared the target in ReleaseSafe
using the daemon's existing Zig options; execution remains unrun. These predicates do not prove
original package/source provenance, ELF launch form, installed application
behavior, provider access, native history preservation or same-process handoff.
