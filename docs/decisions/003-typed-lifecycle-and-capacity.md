# ADR-003 — Typed lifecycle and generic capacity

Status: ratified direction, 2026-10-02; experimental and unshipped.

**Existing user decision.** Identity, account, source, grant, resource, observation, binding and lease are distinct. Authentication factors are enrollment requirements, not grants; labels are not identity authority. Resources cover calls, bytes, uploads, duration, rates and scoped provider capacity, beyond LLM quotas.

**Implementation choice.** Typed provider/application adapters verify identity, declare grants and observations, and own protocol boundaries. Automatically enroll verified identities within authorized sources; quarantine ambiguity. Detachment retains history and independently valid grants. Pause, drain, forget and upstream revocation have separate effects; forget removes secrets and leaves an explicit-reenrollment tombstone. One writer renews each adopted grant; import alone transfers no ownership.

**Acceptance / unresolved proof.** Lifecycle, grant validity, entitlement, capacity and readiness must remain independent, with unknown/stale observations visible. Local fixtures cover these distinctions; real provider identity/adoption, units/windows, renewal reconciliation and capacity freshness need provider-specific evidence. Adapter declarations do not create support.

Authority: [reset, domain and lifecycle](../plans/omux-native-account-lifecycle-reset-2026-10-02.md); [domain source](../../src/domain.zig); [evidence](../implementation/native-reset-evidence-2026-10-02.md). Related: [ADR-002](002-local-compatible-account-federation.md), [ADR-005](005-custody-and-runtime.md).
