# Ratified native-reset decisions

These records capture existing user decisions and the active [2026-10-02 reset](../plans/omux-native-account-lifecycle-reset-2026-10-02.md), not new product policy. **Ratified** means architectural direction is settled; it does not mean implemented, released or proven live. [AGENTS.md](../../AGENTS.md) governs conflicts; [implementation evidence](../implementation/native-reset-evidence-2026-10-02.md) records executed predicates separately.

| ID | Decision | Remaining acceptance or decision |
| --- | --- | --- |
| [ADR-001](001-native-application-continuity.md) | Ordinary native launch and native state authority | Exact-version native hook and live same-process proof |
| [ADR-002](002-local-compatible-account-federation.md) | Local compatible federation, sticky routes, acceptance fence | Provider compatibility and safe-boundary evidence |
| [ADR-003](003-typed-lifecycle-and-capacity.md) | Distinct lifecycle entities and generic capacity | Provider units, identity/adoption and freshness contracts |
| [ADR-004](004-browser-source-conduit.md) | Optional scoped browser data conduit | Verified acquisition schemas and browser-context proof |
| [ADR-005](005-custody-and-runtime.md) | Ciphertext SQLite, OS vault and pinned native runtime | Real vault and platform custody gates |
| [ADR-006](006-thin-native-clients.md) | SwiftUI/Qt control clients | macOS execution and installed desktop/service proof |
| [ADR-007](007-local-declared-execution.md) | Nix/Bazel local graph; no automatic CI | Cold-cache/platform closure and future RBE operation |
| [ADR-008](008-generated-spa-authority.md) | Generated separate SPA, repository runtime authority | Evidence-bound bundle reconciliation and publication |

All records are ratified on 2026-10-02 for the experimental, unshipped successor. The July [full-broker program](../plans/oauth-mux-v0.2-full-broker-foss-program-2026-07-11.md) and its wrapper/managed-launch, optional-daemon, remote/GF-first and Just execution direction are superseded where they conflict. Historical release claims and evidence remain intact; these ADRs confer no inherited live capability.

Implementation choices below describe the current reset design, not authority to add product policies. Unresolved proof remains a gate even where source or fixtures exist. Future product changes require explicit authority and a successor decision; new test receipts belong in the evidence record.
