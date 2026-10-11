# ADR-008 — Generated separate SPA and runtime authority

Status: ratified direction, 2026-10-02; experimental and unshipped.

**Existing user decision.** `omux.xoxd.ai` is a separate downloads/documentation SPA. This repository owns API, CLI, capabilities and release facts; website rendering cannot create runtime claims. The npm distribution lane remains retired.

**Implementation choice.** The current versioned generated bundle exports product/release metadata, CLI usage summaries, control API method names/summaries/channels, adapter capability declarations and lifecycle summaries from source catalogs. It does not yet export per-method parameter/result schemas, examples or support-evidence receipts, or the separate browser/native-owner wire contracts. Complete source-derived schemas, examples and evidence references remain the reset's required generated-documentation scope. The SvelteKit SPA consumes the emitted bundle; curated intent/lifecycle prose remains authored. The current producer emits unstamped provenance (`sourceRevision: null`, `sourceDirty: true`); a bundle digest detects byte drift without attesting source cleanliness or release authority. Release tags, changelog and committed evidence retain authority over shipped claims.

**Acceptance / unresolved proof.** Bundle generation and SPA drift checks establish reconciliation, not live integration support or publication. A named capability, schema or UI does not promote a stub or candidate to supported status. Keep source implementation, synthetic checks, native conformance and live-provider evidence distinct. Publication and evidence-bound release promotion remain explicit operations.

Authority: [reset, generated documentation](../plans/omux-native-account-lifecycle-reset-2026-10-02.md); [reference producer](../../src/reference.zig); [release history](../../CHANGELOG.md); [evidence](../implementation/native-reset-evidence-2026-10-02.md). Related: [ADR-007](007-local-declared-execution.md).
