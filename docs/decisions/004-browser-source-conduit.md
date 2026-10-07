# ADR-004 — Optional browser source conduit

Status: ratified direction, 2026-10-02; experimental and unshipped.

Channel boundary clarified 2026-10-05; source-level contract, not installed proof.

**Existing user decision.** Chromium/Firefox extensions are optional authorized data conduits, not browser automation or general extraction. Browser source read permission does not authorize API use. Safari and arbitrary-provider acquisition are deferred.

**Implementation choice.** Request narrow provider permissions and use native messaging. Import only declared cookie/storage fields, retain origin/store/partition/security/expiry context, and verify identity at a fixed declared endpoint before binding. Encrypt persistence and return opaque handles. Browser-bound grants retain their signing authority and report `browser_required` when absent; page readers expose declared typed observations and disable on schema drift.

**Acceptance / unresolved proof.** Production exports remain disabled pending verified provider schemas. Synthetic extension/bridge fixtures and unsigned packages do not prove browser installation, real import or continuity. Live consent scope, identity, context binding and expiry behavior require evidence. Browser closure and source detachment cannot be mistaken for upstream revocation.

**Mandatory wire-1 channel contract.** Every browser envelope, including health,
contains typed `params.provenance.channel`, exactly `release` or `development`.
The packaged extension owns this value. Missing, unknown and cross-channel values
are refused, without an implicit release default. Previously unsigned, unshipped
component combinations that omit the field require matching extension, native-
host and daemon updates even though the wire version remains 1. The native host
checks the selected instance before forwarding. The daemon independently checks
the channel before browser mutations or production-schema-proof refusal
accounting; host checks cannot waive this boundary.

**Compatibility is not identity.** The extension performs health preflight on the
same native messaging port used for the operation and requires compatible wire
version, channel and capabilities. This establishes peer compatibility for that
port, not browser principal identity or account-use authority. Registration and
transport boundaries, scoped source consent and provider identity verification
remain distinct. Installed-browser channel/refusal proof is still required.
Browser-port closure and extension uninstall have no proved authority-removal
effect; they must not be reported as completed Disconnect or upstream revoke.

Authority: [reset, browser acquisition](../plans/omux-native-account-lifecycle-reset-2026-10-02.md); [extension boundaries](../../extensions/README.md); [evidence](../implementation/native-reset-evidence-2026-10-02.md). Related: [ADR-003](003-typed-lifecycle-and-capacity.md), [ADR-005](005-custody-and-runtime.md).
