# ADR-008 — Generated separate SPA and runtime authority

Status: ratified direction, 2026-10-02; experimental and unshipped.

**Existing user decision.** `omux.xoxd.ai` is a separate downloads/documentation SPA. This repository owns API, CLI, capabilities and release facts; website rendering cannot create runtime claims. The npm distribution lane remains retired.

**Implementation choice.** A versioned generated bundle exports schemas, CLI reference, adapter capabilities, examples, support evidence and release metadata from current source definitions. The SvelteKit SPA consumes that bundle; curated intent/lifecycle prose remains authored. Release tags, changelog and committed evidence retain authority over shipped claims.

**Acceptance / unresolved proof.** Bundle generation and SPA drift checks establish reconciliation, not live integration support or publication. A named capability, schema or UI does not promote a stub or candidate to supported status. Keep source implementation, synthetic checks, native conformance and live-provider evidence distinct. Publication and evidence-bound release promotion remain explicit operations.

Authority: [reset, generated documentation](../plans/omux-native-account-lifecycle-reset-2026-10-02.md); [reference producer](../../src/reference.zig); [release history](../../CHANGELOG.md); [evidence](../implementation/native-reset-evidence-2026-10-02.md). Related: [ADR-007](007-local-declared-execution.md).
