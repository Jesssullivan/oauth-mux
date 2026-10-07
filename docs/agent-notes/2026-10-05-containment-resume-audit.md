# Resumed containment acceptance audit — 2026-10-05

ID-CONTAINMENT is **passed for the current finite local admission profiles**.
Actual qualified SPA admission now completes the evidence chain that was missing
at the earlier resumed audit. Failed dependency analysis and failed installed
custody remain failed product results; they do not negate observed resource
limits, admission ordering or verified cleanup.

Authority: the user's October 5 implementation and resumed-execution instruction;
[AGENTS](../../AGENTS.md); the exact ID-CONTAINMENT acceptance predicate in
[the integrated delivery plan](../plans/omux-integrated-delivery-sprint-2026-10-05.md);
R-HOOK-CONVERGENCE-20261004, R-N11/R-N12/R-N13. Root authorized this independent
read-only reassessment and durable update of this gate alone. Hooks remain
advisory diagnostics, not approval gates. This audit ran no build, test,
generator, package, workload or new qualification probe.

## Closing predicate and scope

The plan requires effective memory/PID/swap/CPU/time limits verified before
workload admission; exact owned process scopes empty after cancellation and
failure; and external execution dispatch excluded or independently bounded.
It does not require a successful application test or complete dependency closure
to establish a failed workload's containment.

The qualifying current profiles are finite local standard/dependency execution
and the separately qualified SPA admission path. Each admitted workload retains
4,294,967,296-byte memory, zero swap, 512-task, two-CPU and 1,200-second bounds;
the unprivileged worker has empty ambient and bounding capabilities. Current
`tools/execution_guard.py` verifies systemd properties and actual kernel cgroup
memory/swap/PID/CPU values before writing the worker's `go` marker. The
supervisor remains outside the exact UUID workload scope and verifies that
scope empty after termination.

Host manager, user/system D-Bus and Nix daemon delegation are blocked by the
verified read-only mode-zero bounded masks. The SPA path additionally masks
`/etc/bluetooth` and excludes `/etc/environment`. Native Bazel/JDK inputs are
independently byte/closure qualified. Batch dispatch excludes ambient system,
home and workspace rc files. SPA build/test dispatch explicitly sets empty
remote executor/cache and local sandboxed strategies. This proves exclusion of
external execution delegation, not absence of public artifact retrieval.

The **only SPA network exception is the exact LOCK phase**, admitted solely as
`mod deps --lockfile_mode=update` against the fixed registry selections. It
regenerates dependency metadata; it dispatches no application build or test.
All other inspected SPA phases retain `PrivateNetwork=yes`. This closure does
not qualify a future FETCH phase or another changed profile.

## Retained actual evidence

Historical receipt root **H** is
`/home/jess/.local/state/omux-execution-20261005/`; current SPA/qualification root
**F** is `/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/`.
Each tuple below identifies the actual retained `ROOT/EPOCH/receipt.json`.
Earlier statuses and unsuccessful workloads remain unchanged.

| Root / epoch | Observed predicate and process result |
| --- | --- |
| H / `80a8c353-0939-4158-9f73-8a8e926d08c9` | Effective kernel bounds and host identity verified; live delegation probe returned EACCES for all five manager/D-Bus/Nix socket connections; controller exit 0 and empty descendants. `probe-delegation.json` retains the exact denial results. |
| H / `e9cf87a2-90a5-40a5-bf4c-be2023ed11db` | Cancellation cleaned two exact owned children in separate sessions before self-expiry; receipt/workload 125 and empty descendants. Outside readback found recorded supervisor/children/cgroup absent. Evidence SHA256 `0b7c02a980312990613538db386aa216319aa2a0efb48396dbc3710cd607efe1`. |
| H / `8e61c577-d7dc-4075-8bab-1061cc92620f` | Finite 9 MiB overflow stopped before the 8 MiB retained-log cap; receipt/workload 125, empty descendants and outside exact-scope absence. Evidence SHA256 `da5a48f16630778e849714c87952b5491fe3262f61eb2909ed6ed9a3bb27184e`. |
| H / `a93d1778-3469-4be6-be27-0bc3dcb409ff` | Fresh resumed standard admission and effective limits/masks; selected source/protocol/process-cleanup/admission tests passed; controller/workload 0, empty descendants. Graph SHA256 `ec5ccbade4a739743dfe9c2e3c1cc43f8058eeb6ab5195c777a504f84b9bf4c4`; evidence SHA256 `3a0eab0bfbbc5ec1e45c40b01b2a11a319c219fbf03641125f4b3fe5ff2cb70e`. |
| H / `4cf338e5-a630-4c6c-b869-ceb2ad5c9e9d` | Current execution-guard, finite-site and dependency-profile predicates passed; installed custody remained failed. Overall controller/workload 3 with empty descendants. Graph SHA256 `4a271f7feee4564af71dc46c89408629b20cde7a362b96fc6afd1d98c24e4595`; evidence SHA256 `ac0e2392a15d30f7439fda30787bc01d47d9c28d3f84cd1b6529339d55538d93`. |
| F / `f3c76f3f-aff4-4953-b91a-216012c9e2f7` | Actual `//tools:site_coordinator_closure_qualification` and `//tools:codex_dependency_bundle_plan`; controller/workload 0, empty descendants. Coordinator report establishes complete selected Bazel/JDK closure and byte/version qualification, not independent execution authority. Evidence SHA256 `29a5c7b228fa0a4af0010f34b28ce76600964a7d8bb9f8f8831fadcbd2f73fc5`. |
| F / `2eb92a24-b91f-43ae-810c-70901d40d3c3` | Actual exact SPA LOCK admission; effective limits, identity and masks verified; controller/workload 0, empty descendants, no controller failure. Controller graph identical before/after; only `MODULE.bazel.lock` changed; final source verified after cleanup. This is the closing actual selected-profile tuple. |

The closing tuple uses native Bazel 9.0.1 and OpenJDK 21.0.10+7, joined through
coordinator qualification SHA256
`3e8184da017f41b90ddab42972111a930be4a4e53bbdff7df9de493386583a6b`.
The qualified report identifies `closure_verified=true`,
`content_rehashed=true`, `binary_versions_verified=true`, `realized=false` and
`execution_authority=false`; the actual guard admission supplies execution
authority. Bootstrap/closure manifests are respectively
`c056b1b590c814bc662a7ef348ba4f5789e3534ed9ae8420fdc8614fefd9bc3a` and
`7f19ccff61a0d5981641a73ab65067eac6de77e13e146b4be06ac6b36652bd41`.

Exact controller graph before/after:
`cb4e35a64a12b67dc958ca59d435111056668aad82569ca029af9c4f93bc33c9`.
SPA source snapshot before:
`7acd0f99130c1ae6763d2eca999ff749405e0920182295e6b54e84d519d6980d`;
after: `e84cdff1a334accb310791444dc4b6ceb225e4ad873e07ffeba24161618c3215`.
The receipt preserves raw `site-MODULE.bazel.lock.before` (67,215 bytes,
SHA256 `1e660bd9c4f65b787240494916e7b4bc2b32212cf984cfa2dd9020a387e05097`)
and `.after` (107,422 bytes, SHA256
`9502d4b346dbe26c8652e6bee818c22e1d3002bdbe97fbec28dc598a2236b82d`).
These are exact graph/source-inventory bindings, not a claim that every runtime
source in the worktree is frozen or product-tested.

Separate actual SPA qualification failures also confirm failure cleanup:
F / `359c16da-c48e-4dda-8101-ea16d5df2af5` returned 48 on stale lock metadata;
F / `bbb9a819-95a9-44b4-a048-4b8f694f3844` returned 1 on an unavailable offline
dependency. Both have empty descendants, unchanged respective source snapshots,
final source verification and no controller failure. The latter dispatched
zero actions/tests; no passing SPA payload is inferred.

## Limits and durable reconciliation

The 2,147,483,648-byte free-space floor is sampled monitoring with possible
overshoot, **not an aggregate disk quota**. Child file bounds and retained-log
bounds do not convert it into such a quota. This audit closes the stated
memory/PID/swap/CPU/time/delegation/cleanup gate; it makes no stronger disk claim.

The historical partial entry remains intact in
[the goal ledger](../../.goal/omux-integrated-delivery-2026-10-05.json), with this
closing audit appended only to ID-CONTAINMENT. The
[resume receipt](../tracker-updates/integrated-delivery-resume-2026-10-05.json)
and [session record](2026-10-05-sess-omux-integrated-delivery.md) retain earlier
blocked, refused, partial and successful epochs. Root owns their subsequent
tracker/summary reconciliation; this audit does not mutate Linear.

No other gate is promoted. Installed custody, browser consent, fleet activation,
SPA application tests/rendering, native delivery/resume and live handoff retain
their independent results. Provider authorization, Darwin/PZM execution and
publication remain separate; this receipt establishes no shipped support,
achieved SLO or contractual SLA.

## Finite FETCH extension qualification — 18:16 UTC

The earlier LOCK-only closing tuple remains its dated scope. The subsequently
implemented FETCH extension has now passed current guard30 and site-profile15
predicates in `18f25c5a-044d-431f-9678-65fcfcc2db57`, independent read-only
review against pinned Bazel9.0.1 FetchCommand/TargetFetcher/BuildRequestOptions,
and actual admission in `0d13846b-9ccc-4c5a-8762-dbf2392521a3` under root F.
The actual finite nine-target fetch returned controller/workload0, empty owned
descendants, no source changes, identical source snapshots and final verified
cleanup; all selected dependencies were fetched. Its controller graph is
`e3e34ef75635d7cb1df122a35d41205a3a1668e77d182525d0758e7e96937079`.

FETCH and LOCK are the explicit SPA network exceptions. FETCH enforces
`--nobuild`, lockfileerror and zero permitted source mutations. Bazel reported
684 loaded packages,29,905 configured targets and zero target actions/processes.
Repository rules/module extensions may execute declared acquisition helpers
inside the same bounded/masked scope; no target build/test/import action follows
from fetch success. The external delegation exclusion, global coordination
lock, complete native toolchain qualification and sampled-floor limitations
remain unchanged. This fresh tuple qualifies the new finite FETCH containment
path; it establishes no passing SPA payload or product gate.
