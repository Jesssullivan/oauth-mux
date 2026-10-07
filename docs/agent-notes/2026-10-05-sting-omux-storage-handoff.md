# Sting Omux storage handoff for the Neo operator

Current status: **storage prerequisite resolved; execution resumed** at 16:03
UTC after user confirmation and path-specific readback. Home had
29,655,379,968 bytes and project 177 had 232,281,415,680 bytes available. Root
performed no quota/GC action and infers no operator cause. The historical unsent
allocation request below no longer blocks current dispatch. See the
[resume evidence](../tracker-updates/integrated-delivery-resume-2026-10-05.json).

## Historical allocation request

User authorized a Neo Claude/operator query or a handoff they can pass along.
No Claude connector is exposed here; this handoff was written, not sent.
Authority: repository `AGENTS.md`, R-N11/R-N12/R-N13 and the user-authorized
[15-hour implementation plan](../plans/omux-integrated-delivery-sprint-2026-10-05.md).
The [goal ledger](../../.goal/omux-integrated-delivery-2026-10-05.json) runs
2026-10-05 04:03:36–19:03:36 UTC. The allocation hold described below blocked
declared execution; its resolution establishes no native/browser product pass.

Please inspect project **177** block/inode quota usage, soft/hard limits and
grace state, and reconcile or provide a declared dedicated allocation with
**at least 32 GiB usable headroom** for Omux source preparation, SDK compilation
and installed Chromium proof. Return the exact nonsecret path, ownership/mode,
project ID, limits and effective free-space readback. This is a request for an
operator proposal; no quota/project/mount change or GC has been performed.
Do not provision an undocumented quota bypass or delete another workstream.

## Updated local execution stop — 2026-10-05 12:44 UTC

The home fallback also crossed its unchanged 2 GiB free-space floor. Epoch
`bc1fa374-04b6-4754-ac2e-1c8fdaddd93f` was stopped with workload/exit 125,
empty descendants and preserved evidence. The installed core native-messaging
test had no test directory and remains unrun. Exact byte readback now:

| Path | Available bytes |
| --- | ---: |
| `/home/jess/.local/state/omux-execution-20261005` | 2,107,031,552 |
| `/srv/fast-local/jess/state/codex` (project 177) | 0 |
| `/srv/fast-local` (mount root) | 563,854,028,800 |

Please include the home fallback in allocation planning. Root is continuing
source and tracker reconciliation; payload execution is held. Preserve its
successful staged development generation and all qualified mapping, NAR,
candidate-settings, native-version and SDK-settings inputs. No quota, mount,
GC, foreign process or storage configuration action has been taken.

## Observed storage boundary

Both paths use `/dev/mapper/sting--nvme--fast-local--path--fast`, XFS mounted at
`/srv/fast-local` with `prjquota`. `lsattr -pd` shows project 0 at mount root and
inherited project **177** (`P`) on `/srv/fast-local/jess`, `state` and `state/codex`.
Earlier exact readback: mount total 1,717,148,057,600 bytes / available
581,419,696,128; owner state total 1,127,428,915,200 / available 1,625,128,960.
Latest handoff readback: mount available **576,713,097,216 bytes**, owner state
available **0**, `/home` available **4,262,539,264 bytes**. These are different
project-specific `statvfs` views, not evidence that the device shrank. An
unprivileged `xfs_quota` query returned no usable quota report. No filesystem
fault, other job, GC event or limit change is inferred.

Root reports epoch `5885121b-b5d3-4f5b-9c55-1c92295e8428` exited with clean descendant closure;
scoped process inspection found no active Omux guard/build. Before any operator
action, recheck that no new epoch has started. No process/service was signalled
for this handoff.

## Exact task roots and protected custody

- Current fast execution state:
  `/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005`.
- Home coordination and bounded execution state:
  `/home/jess/.local/state/omux-execution-20261005`; preserve its global
  `execution.lock` coordination semantics across any new allocation.
- **Protect fresh source** under fast epoch
  `cf85bdc6-5de0-4033-a57e-5e8d24301ccb/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/codex_fresh_source_producer/test.outputs/codex-adapter-epoch/`.
  Retained inventory: 8,546 files / 84,615,686 bytes; source receipt SHA256
  `6a606a9ca602e31f0050d15625038eeaaaff96432248dd803d51c3a1838871b3`.
- **Protect archive bundle**:
  `/srv/fast-local/jess/state/codex/omux-dependency-prefetch-20261005/052fde9c-7e07-490f-a940-fb11820f1d31/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/fetch_codex_archives_bundle/test.outputs/bundle/`.
  Thirteen verified archives / 423,094,090 bytes; receipt SHA256
  `1d3d34323a3e19fd7e640146bf0eba006881a9bdd2d376a0493153f4cd8d30a0`.
- **Protect old SDK source and original binaries**:
  `/srv/fast-local/jess/state/codex/omux-codex-owner-development-20261004`,
  `/srv/fast-local/jess/state/codex/omux-codex-native-recovery-development-20261004`,
  and their output roots `omux-bazel9-codex-owner-20261004/fb3edda211c2b41f7c6600796d3b28d1`
  and `omux-bazel9-codex-native-recovery-20261004/f857293521e27a22b6cefdd38c39173f`
  beneath the same `state/codex` directory. Original fastbuild/optimized ELF,
  schemas, receipts and input bindings remain required until fresh native
  compilation establishes replacement custody.
- Preserve all logs/evidence and shared/dirty caches. The failed unique fast
  epoch `802f910e-c1c9-44b9-a862-614b598be0f7` has only **61 MiB** of derived
  output; retiring it would not restore the required floor. Its helper was
  authored but explicitly stopped before execution. No cleanup is requested
  here. Earlier fixed cancelled-browser cleanup completed under `c846…` and
  preserved its debug/compiled inventory and epoch evidence.

## Execution conditions after allocation

Keep the root-owned serialized locked Nix/Bazel action graph and verified
controller admission: **4 GiB memory**, **512 tasks**, **20-minute maximum**,
no swap allowance and verified descendant cleanup. Effective state-path
preflight and sampled running free-space floor is **2 GiB**; earlier 8 GiB
aggregate/4 GiB floor wording was proposed, not an implemented guarantee.
Measure the actual allocation path rather than mount-root free space. Do not
reduce these limits to force a blocked dispatch. New source/artifact custody
must be receipt-bound before any old input retirement.

Delivery carriers: [TIN-2063](https://linear.app/tinyland/issue/TIN-2063) for
installation/deployment and [TIN-5338](https://linear.app/tinyland/issue/TIN-5338)
for the Omux-developed native adapter and exact application proof.
[Session evidence](2026-10-05-sess-omux-integrated-delivery.md) and
[estate audit](2026-10-05-sess-omux-estate.md) distinguish passing component
checks from unrun native compilation, ordinary launch/resume and live handoff.
Root reconciles this handoff into authority classification after the document
freeze. No message, service action, mount change, quota edit or GC was executed.

## Current block audit — 2026-10-05 14:05 UTC

At 14:04:49 UTC the home allocation had **2,085,203,968 bytes** available,
project 177 **zero**, mount root **559,476,682,752 bytes**. These current readbacks
supersede the earlier temporal availability observations for dispatch decisions.

The full tool goal was marked **blocked** at 14:05:10 UTC following repeated
allocation refusals and independent full-objective audits. It remains incomplete:
one written authority gate passed; ten implementation/installed gates remain
open. Original 15-hour start/checkpoints/due time and all evidence are retained.
Source is frozen, all new predicates unrun, no live root dispatch handle exists,
and no automatic retry is scheduled. This saved handoff is still **unsent**.

Return the scoped declared allocation facts requested above. Any later resumed
dispatch must preserve the global home coordination lock and unchanged controller
admission. Allocation is necessary but not sufficient for Home Manager inputs,
fresh native compilation/selection/attribution, provider limits or the held
GF-owned Darwin lane. See the [full audit](2026-10-05-sess-omux-integrated-delivery.md#ten-hour-checkpoint-and-full-objective-block-audit--1405-utc).

## Allocation restored — 2026-10-05 16:03 UTC

User confirmed contention resolved and resumed the full goal. Current effective
readbacks: home **29,655,379,968 bytes**, project 177 **232,281,415,680 bytes**,
mount root **536,853,876,736 bytes**. The allocation request is no longer blocking
current guarded qualification. Root performed no quota/GC/allocation action;
the change's operator provenance is not inferred. Preserve the original lock,
limits and protected inputs. Earlier block audits and unsent-handoff facts
remain historical; new acceptance still requires exact execution evidence.
