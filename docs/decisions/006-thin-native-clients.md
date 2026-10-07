# ADR-006 — Thin SwiftUI and Qt clients

Status: ratified direction, 2026-10-02; experimental and unshipped.

**Existing user decision.** A resident per-user daemon owns lifecycle, grants, policy and routing. SwiftUI/macOS, Qt6/Linux, CLI and browser clients are thin; closing a client leaves the daemon running. Disconnect, uninstall and restoration are explicit operations.

**Implementation choice.** Native controls share the versioned redacted control API for sources, accounts, bindings, grouped capacity, policy and repair. Show unknown/freshness states and missing native hooks; notify on meaningful transitions. Clients do not independently invent capacity totals or collect authentication factors. Desktop service registration is an explicit setup operation.

**Acceptance / unresolved proof.** Linux widget/transport fixtures establish their narrow predicates. Installed tray/service behavior and macOS compilation/execution remain separate gates; Linux bundle fixtures cannot establish SwiftUI execution. UI presence and an attach button never establish native attachment capability. Reversible integration removal and native-store preservation require acceptance evidence.

Authority: [reset, clients and interfaces](../plans/omux-native-account-lifecycle-reset-2026-10-02.md); [client implementation boundaries](../../clients/README.md); [evidence](../implementation/native-reset-evidence-2026-10-02.md). Related: [ADR-001](001-native-application-continuity.md), [ADR-005](005-custody-and-runtime.md).
