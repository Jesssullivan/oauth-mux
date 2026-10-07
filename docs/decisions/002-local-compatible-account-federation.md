# ADR-002 — Local compatible account federation

Status: ratified direction, 2026-10-02; experimental and unshipped.

**Existing user decision.** Federate authorized accounts in userspace within one user's local daemon. Technically compatible accounts are eligible by default; users may narrow policy. Keep active routes sticky and alternatives ready. Cross-host federation and universal process interception are outside this reset.

**Implementation choice.** Adapters describe exact resource demand and verified native boundaries; the daemon owns routing and leases. Aggregate only compatible units, scopes and windows, counting a shared quota bucket once. Native account-bound transport references must be invalidated when a route changes without replacing native session authority.

**Acceptance / unresolved proof.** Only proven pre-acceptance failures can admit safe substitution. Never replay an accepted stream, repeat tool execution or treat ambiguous network failure as permission to retry. Account-bound opaque context requires a demonstrated safe reconstruction path or explicit refusal. Warm alternatives, route-election fixtures and restarts do not prove continuity. Provider compatibility, rejection semantics and version-bound live handoff remain evidence gates.

Authority: [reset, lifecycle and native integration](../plans/omux-native-account-lifecycle-reset-2026-10-02.md); [evidence](../implementation/native-reset-evidence-2026-10-02.md). Related: [ADR-001](001-native-application-continuity.md), [ADR-003](003-typed-lifecycle-and-capacity.md).
