# Live-account implementation checkpoint — October 7

Authority: the user's five-hour real-account proof instruction and live model IO authorization, [AGENTS](../../AGENTS.md), the [architecture SSOT](../plans/omux-native-account-lifecycle-reset-2026-10-02.md), and R-HOOK-CONVERGENCE-20261004/R-N13.

The checkpoint runs **05:48:41–10:48:41 UTC**. It continues the incomplete original fifteen-hour objective; historical clocks and five scoped passes/six open gates remain preserved. The [checkpoint ledger](../../.goal/omux-live-account-proof-2026-10-07.json) and [execution/tracker receipt](../tracker-updates/live-account-proof-2026-10-07.json) own current results.

## Honest product position

PR531 merged reviewed diagnostics as `d829b3cdd91696a375a076970214fbf0621a5f6c`. Seven focused diagnostic/guard/source targets passed; the fresh native run `e761fae3-bbf4-4c68-af4c-23075c43bab7` failed after seed/history/detach, when the cold resumed terminal exited before its owner endpoint. Yoga registry metadata refused before content rehash. Neither run establishes ordinary native resume or live handoff. Durable real-account enrollment has not yet been established. Current code has native source import, authenticated provider identity verification and encrypted access-grant custody; these require actual evaluation.

## Work order

1. Discover the explicitly authorized working native source; enroll and verify two real identities into private custody. The user does not have to know profile paths. Existing native credentials are read only by the authorized daemon. New account sign-in uses a fresh isolated native profile because Codex login can revoke existing auth before enrollment. Never invoke login against the active working profile.
2. Resolve the cold-resume failure with closed error/exit classification, then preserve all original native history/configuration/identity predicates. Implement the minimum live execution and native request audit boundaries alongside it.
3. Qualify text portability and completion ordering on the exact maintained candidate. Account-bound reasoning/files/tool artifacts must never be silently treated as portable. Native history remains authoritative and accepted work is never replayed.
4. Prove successful real text turn A, deliberate completed-turn drain, then successful real turn B without changing PID, native thread/history or approval authority. Label the cause `operator_drain`; this does not close provider-originated automatic fallback, concurrency or tool-execution acceptance.
5. Deliver reviewed source and exact evidence through signed source/PR plus factual [TIN-5338](https://linear.app/tinyland/issue/TIN-5338), [TIN-5421](https://linear.app/tinyland/issue/TIN-5421), [TIN-1818](https://linear.app/tinyland/issue/TIN-1818), [TIN-1798](https://linear.app/tinyland/issue/TIN-1798) and [TIN-2057](https://linear.app/tinyland/issue/TIN-2057) updates. Failed gates remain open.

Root is the single execution coordinator. Restored Sol6.1 implementation/review agents write separate unapplied proposals in the original mixed checkout; root applies reviewed changes to the owned clean source branch. The original index/worktree is preserved. All execution remains locked Nix/Bazel with aggregate4GiB, swap0,512 tasks,CPU2,1200-second deadline and batch Bazel. A live network exception must be explicit and separately qualified; offline profiles retain network denial. No broad credential scans, raw native output, provider identifiers or account addresses enter evidence.

The user authorizes model IO without a token-spend cap. Choose an available small model and begin with short text-only turns; engineering request/time bounds remain finite. Browser/HM-wide delivery, Darwin, additional integrations and public distribution continue as independent product obligations but do not lead this live-proof critical path. SLO/SLA claims remain unchanged.

## First source action

Source delivery uses per-invocation `core.hooksPath=/dev/null` under R-N12,
with independent signed-commit verification, explicit staging, contained Bazel
checks and exact source/tree readbacks. Global hooks/remotes remain untouched.

Applied the reviewed failure-only terminal observation to `delivery/test_installed_native_tui.py` and `delivery/test_installed_legacy_native_tui.py`. It emits closed exit/message categories only before existing cleanup; it changes no native acceptance, timeout or ownership predicate. Its privacy models and original native checkpoint are still unrun on this source.
