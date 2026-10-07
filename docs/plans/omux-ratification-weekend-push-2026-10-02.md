# Omux ratification and weekend acceptance push

Status: **dated acceptance objectives, not completed future work**. This plan
records the requested three-hour, five-hour, ten-hour and end-of-weekend goals.
The umbrella goal is tracked once; [.goal ledger](../../.goal/omux-weekend-2026-10-02.json)
records its subordinate milestones. Neither file installs timers, dispatches
future work or creates four independently active goals.

Start: **2026-10-02 23:41:49 America/New_York**
(`2026-10-03T03:41:49Z`). These are checkpoints, not guarantees that every
platform/provider gate can be completed by a clock deadline.

## Authority and outcome

Ratify the existing product contract into reviewable source documents and an
actionable implementation backlog: install once, authorize account sources once,
and use ordinary applications with compatible same-process handoff. Applications
need no Omux launch wrapper. Native session/history/tool/approval authority stays
in place. Missing native hooks remain visible. No deadline authorizes replay of
accepted streams, repeated tool execution, weaker custody or broader claims.

[AGENTS.md](../../AGENTS.md), the [active reset](omux-native-account-lifecycle-reset-2026-10-02.md)
and [authority map](../authority-map.md) govern implementation. The
[charter](../product/charter.md), [user stories](../product/user-stories.md) and
[support acceptance definitions](../product/support-and-completeness.md) consolidate
existing intent; they do not invent user approval, service commitments or shipped
support. Historical release claims retain their original evidence.

## Sequenced checkpoint gates

| Checkpoint | Due locally / UTC | Required pass gate |
| --- | --- | --- |
| H3: contract ratification | Oct 3 02:41:49 EDT / `2026-10-03T06:41:49Z` | Charter, user stories and support/completeness definitions agree with the active reset; authority/subtraction disposition identifies superseded wrapper, optional-daemon, GF/remote-first and obsolete execution assumptions. Every claim distinguishes intent, implementation, synthetic proof and live support. Open decisions and missing evidence remain explicit. |
| H5: existing-project backlog acceptance | Oct 3 04:41:49 EDT / `2026-10-03T08:41:49Z` | Uplift the existing Linear project and reconcile its backlog within authorized tracker scope. Record exact project/issue references and dispositions; preserve useful intent/evidence, supersede conflicts, identify dependencies and attach concrete acceptance gates. Avoid duplicate projects and fabricated owners. If connector/access authorization is unavailable, retain a concrete local reconciliation and mark the external gate blocked. |
| H10: durable local acceptance readiness | Oct 3 09:41:49 EDT / `2026-10-03T13:41:49Z` | Reconcile the current local build/test receipts with the final source scope, record what changed after the last receipt, and run necessary local gates through locked Nix/Bazel. Prioritize blockers for installed daemon/vault/native proof; every remaining item has a bounded next action, required resources and evidence predicate. Do not repeat passed gates absent a relevant change or concern. |
| Weekend: installed/native acceptance decision | Oct 4 23:59 EDT / `2026-10-05T03:59:00Z` | Complete authorized and available clean-machine, real-vault and exact-native/provider acceptance gates, or publish their explicit blocked/unrun disposition with prerequisites. Promote only the exact passing tuple; keep the successor experimental wherever gates remain unmet. Reconcile generated claims, delivery/restoration and release scope before any separate publication decision. |

Later checkpoints depend on accepted earlier contracts; a passing document gate
does not satisfy implementation or live gates. A milestone is passed only when
its actual deliverables and receipts exist. Deadline passage is not evidence.
The root ratification task may finish once its authorized present work is done;
future weekend objectives remain recorded rather than being falsely completed.

## Baseline and evidence work

The [current evidence record](../implementation/native-reset-evidence-2026-10-02.md)
reports 37 project test targets and 66 build targets passed, eight native Codex
candidate builds, 64 focused Rust cases and 318 protocol cases with one intentional
ignore, seven development SPA gates and Linux archive relocation. Those receipts
are baseline evidence, not execution performed by this plan or proof of installed
support. This working-tree reset remains experimental and unshipped.

Necessary execution uses the declared graph:

```sh
nix develop --command bazelisk build //...
nix develop --command bazelisk test //...
```

Use narrower declared targets when a changed predicate warrants them. All
generators, packaging and executable checks likewise run through Nix/Bazel.
No automatic CI, legacy scripts, Just, standalone Zig build or remote dispatcher
is part of this push. Evidence binds source revision/dirty state, artifact digest,
application version/commit, command/action, platform, observed result and limits.
Never store credentials, raw account identifiers or PII in receipts.

## Weekend proof order and blockers

1. **Installed platform and custody:** obtain an authorized clean environment and
   real Secret Service or macOS Keychain. Exercise SC-01/02/08/09/10: private
   sockets, resident service after client closure, encrypted journals, locked/lost
   key handling, recovery, ownership-safe install/upgrade/removal and restoration.
   Linux relocation and fake-vault fixtures alone leave these gates unrun. The
   [subsequent safety sprint](omux-native-safety-sprint-2026-10-03.md) adds genuine
   private Linux vault and installed daemon/Qt proof, with exact receipts in its
   [evidence](../implementation/native-safety-evidence-2026-10-03.md). These
   components do not complete clean-machine, login-service or desktop acceptance.
2. **Native Codex availability:** establish an authorized exact application build
   exposing the required native hook. The candidate for `rust-v0.157.0`, commit
   `00c972ed5d6ff6499317fd41b7f23605b8e6850d`, is not stock support; Omux ships
   no Codex fork. Without that hook, SC-04/05/06 are blocked, not passed by mocks.
3. **Authorized provider acceptance:** obtain compatible authorized accounts and
   a safe provider evaluation budget. Prove ordinary launch/resume, independently
   safe existing-process attachment where claimed, real pre-acceptance rejection,
   alternate admission, unchanged process and native state, no routine prompt,
   concurrency isolation and no accepted-stream/tool replay. Record the exact
   support tuple and unsafe ancillary/account-bound-state limits.
4. **Other bounded scopes:** macOS needs an authorized Apple SDK/execution host;
   production browser exports need exact provider acquisition schema and verified
   identity evidence. Claude native continuity, refresh adoption/ownership
   transfer and upstream revoke require their own completed implementation and
   evaluation. Keep them blocked or unrun until those prerequisites exist.

The acceptance IDs above refer to the support definitions. Availability and
authorization are evaluated from actual resources; this plan grants neither new
account access nor publication authority. Each blocked gate records the missing
capability/resource, next action and affected claim. There are no invented human
assignments, support agreements or promised completion dates beyond checkpoints.
