# Native input and lifecycle progress — 2026-10-11

Authority: user-requested integrated implementation and estate-review continuation; [AGENTS.md](../../AGENTS.md), [the active native account-lifecycle reset](../plans/omux-native-account-lifecycle-reset-2026-10-02.md), R-HOOK-CONVERGENCE-20261004 / R-N11 / R-N12 / R-N13. This checkpoint records source changes and measured predicates; it creates no release or support claim. It supplements [the original estate review](2026-10-11-estate-review-and-priorities.md) without rewriting its report or failures.

Reviewed current source is clean `b40de9481facc3a68c90aa47dcc174fdaa7d0177`, graph SHA256 `be44787be7463215bd6d63a14e0d5e7128bdacfbbc4959a156cff4d1d89b7db7`. Root is the single project executor. This documentation proposal was prepared through source/receipt inspection only, with no project execution or provider access.

## Adopted source changes

| Source successor | Concrete behavior | Qualification boundary |
| --- | --- | --- |
| `304ecd873154682f9b249c1bba7c2fd79b53b381`, parent `0f90ab58d384e54d5459ce7079fd3187b41cf11f` | Browser permission cleanup persists a validated opaque next-source cursor before work so bounded passes/restarts can reach later contexts. Shared Engine/UI/CLI readiness reports native configuration absent or configured-but-unverified. | The existing 10-second/eight-call cleanup budget remains. The cursor confers no permission or mutation authority; completion_unknown/source-presence work remains open. Locked/poisoned native state remains unknown; configuration and evidence labels cannot produce native-ready. |
| `38fa4f9608c98ab5f6a163efe123d659104eed18`, parent `304ecd873154682f9b249c1bba7c2fd79b53b381` | Query consumers retain a whole-consumer cutoff from original entry; query-tool and metadata-input runfiles aliases bind to exact physical leaves/repository before nofollow reads and rechecks. Adopted actual Engine formatter output. | Strict parser/SHA/alias custody remains. These source corrections do not qualify selected metadata, SDK or a native executable. |
| `62d5ad7e0377bd74221ce37f078ca6616fb52a1c`, parent `38fa4f9608c98ab5f6a163efe123d659104eed18` | All three metadata producer invocation guards return literal booleans for nonempty Bazel environment strings. Added valid/restored-selection and missing/empty/wrong-argv regressions. Adopted actual Zig formatter output and three reviewed enum-builtin migrations. | Global strict `require(value is True)` remains; downstream selection/parser/expiry checks are unchanged. Formatting and migration do not establish native support. |
| `b40de9481facc3a68c90aa47dcc174fdaa7d0177`, parent `62d5ad7e0377bd74221ce37f078ca6616fb52a1c` | Runtime query verification joins one immutable phase from the original guarded entry; the initial genuine declared controller repository is qualified before compiler inventory readback. | Query ends at original entry +600 seconds; runtime work remains +1170 seconds and original cleanup cutoff +1200 seconds. No late verifier renews the clock. This separate correction does not repair the NM1 analysis stall or admit native compiler/runtime dispatch. |

Implementation anchors are `extensions/shared/service.mjs` (`reconcilePermissions`), `src/engine.zig` (`setupSnapshot`), `src/onboarding.zig` (`unverified`), the three metadata producers' `declared_selection`, `tools/codex_protocol_history_query_tools.py` (`consumer_deadline`, `consumer_phase`, `verification_deadline`) and `tools/codex_native_acquisition_runtime_qualification.py` (`main`). The adoption receipts bind exact before/after bytes and independent reviews. All four successor receipts record unsigned commits pushed without force and preservation of the original mixed index and nine protected helpers.

## Actual gates, with failures preserved

Outer/workload exits below are the original recorded exits. Case counts are each suite's reported cases, not installed or provider proof.

| Gate / exact epoch | Source | Actual result | Cleanup scope |
| --- | --- | --- | --- |
| LC1 `ed275aa9-2175-4ab2-81f6-48261f117c33` | `304ecd873154682f9b249c1bba7c2fd79b53b381` | Engine285, onboarding9, setup-verification37 and extension54 PASS; format FAILED. Original exits **3/3** retained. | Generic empty/unproved, readbacks0. |
| DM1 `738922d0-d496-4ffa-a6b5-a78df4891ff2` | `38fa4f9608c98ab5f6a163efe123d659104eed18` | Three metadata/alias families FAILED because the invocation and-chain supplied the final timeout string to strict require; format also FAILED. Query21, SDK-export4, preflight3 and compilation16 models passed. Original exits **3/3** retained. | Generic empty/unproved, readbacks0. |
| DM2 `44e10474-a434-4f73-b02b-1dacb7854d32` | `62d5ad7e0377bd74221ce37f078ca6616fb52a1c` | Protocol metadata22, owner-status metadata/SDK14, acquisition metadata/SDK23, runtime-selection105 and format PASS; **0/0**. | Generic empty/unproved, readbacks0. |
| QD4 `d035af65-c301-4cf0-863c-f01178b00213` | `62d5ad7e0377bd74221ce37f078ca6616fb52a1c` | Genuine declared query-tools descriptor test executed and PASS; **0/0**. This qualifies that descriptor boundary, not downstream metadata/SDK/compiler/package. | Exact owned stop succeeded; verified empty with **two** cleanup readbacks. |
| NM1 `ced22184-d36d-4448-aaf0-b7393907d78d` | `62d5ad7e0377bd74221ce37f078ca6616fb52a1c` | Genuine acquisition metadata attempt hit the analysis deadline at **130 packages / 122992 targets configured**; **125/124**. Zero tests and zero retained metadata outputs; no selector was admitted. | Exact owned stop succeeded; verified empty with **two** cleanup readbacks. |
| RQM1 `5cfd50d3-59b7-4578-ba4a-4378cba82717` | `b40de9481facc3a68c90aa47dcc174fdaa7d0177` | Query26 and runtime-qualification63 models PASS; **0/0**. Declared Bazel work also compiled C and linked `native_peer_runtime_bridge.so`; no maintained Codex executable or genuine runtime qualification follows. | Generic empty/unproved, readbacks0. |

Cgroup absence and descendants-empty observations do not establish verified owned cleanup for the generic rows. Later passes preserve all earlier failed epochs; they do not retrospectively change LC1/DM1 or NM1.

NM1 retained one nonfatal SIGQUIT diagnostic against the exact ownership-verified Java PID/start identity, with prior state preserved, plus one resource sample from the original reserved worker. The sample records memory.current1866424320 / max4026531840 / peak2704281600 bytes, pids31 / max480, zero sampled OOM counters, and CPU throttling counters. This is bounded diagnostic evidence, not a timeout root cause, an OOM attribution or a host-wide health/proof statement. Delivery-dependent source edges remain under review; an observed dependency or successful finite model is insufficient to explain the analysis timeout. Do not retry the unchanged native build or extend clocks/caps to hide the missing diagnosis.

## Product and next-gate truth

Install and activate Omux, authorize sources once, and keep using ordinarily launched terminal applications. Applications need no Omux launcher; Omux owns each adapter and its version-bound authentication boundary. Maintained Codex candidates remain experimental; unmodified Codex continuity remains unestablished. Same-process compatible handoff, native accepted-history resume, preserved process/thread/history and no replay remain the product bar.

Current native metadata/SDK/compile selectors remain null and compiler7/8 remains **HOLD**. QD4 descriptor success and RQM1 model/C-bridge compilation cannot substitute for genuine generated metadata/SDK, plan/query/compiler, package or installed candidate outputs. The next native action is a bounded declared-graph source diagnosis and independently reviewed correction for the actual analysis boundary before a changed-input attempt can be admitted. Runtime phase correction remains separate from that diagnosis.

NV3 at `2026-10-10T18:55:13.403100Z`, source `784ecad7b105f54038bab2634a14bc3a691be6fc`, is the last verified normal-vault observation at this checkpoint: default Secret Service collection exists and is **Locked**. It made no Unlock/Prompt, item, secret, wrapping-key, provider or Omux-datastore call. Resident metadata remains unloaded and current retained account count is null/unavailable; no fresh normal-vault two-account custody is proved. The earlier isolated provider-verified encrypted access-custody/restart proof remains valid within its removed-fixture scope. A dated NV4 metadata-only continuation at b40 is pending independently; observation alone would not prove loaded custody or enrollment.

Production browser exports remain disabled (`extensions/shared/adapters.mjs`); usable browser authority, attended consent/presence and complete installed lifecycle remain open. Production adopted renewal/provider I/O is unimplemented. Genuine current Home Manager realization/activation/update/removal and installed ordinary-launch/resume proof, production Darwin, signing/authentic distribution, deployed web successor and live continuity remain unproved. Historical scoped installed/provider evidence is preserved without transferring it to these successors.

Existing carriers retain separate scopes: TIN-5338/native proof, TIN-2063/install-custody, TIN-5421/discovery, TIN-2057/full continuity, TIN-5442/browser lifecycle, TIN-2720/browser consent and TIN-734/public delivery. The original review's last recorded states remain 5338/2063/2057/2720 In Progress, 5442/734 Todo and 5421 Backlog, with no completedAt; no tracker mutation or fresh tracker read occurred for this note. The original **2026-10-05T04:03:36Z–19:03:36Z fifteen-hour goal remains ACTIVE, overdue and incomplete**. Neither this dated checkpoint nor successful finite models resets it, clears compiler counts or closes integrated/live gates.

## Durable receipt custody

The following files are retained under the exact absolute root `/home/jess/.local/state/omux-proposals-20261010/root/docs/agent-notes/`. Each filename below appended to that root names the full durable artifact. These are plaintext custody references, not repository-linked or newly declared JSON inputs. Hashes in this table bind the root artifacts themselves; the execution receipt hashes in the following table bind their original epochs.

| Root artifact filename | SHA256 |
| --- | --- |
| `2026-10-11-lifecycle-readiness-adoption-pre-action.json` | `20f34d21e980483d8513155405b4eb84bf95cd2bb18fed045b8e4b3fa5343cf9` |
| `2026-10-11-lifecycle-readiness-adoption-result.json` | `e9db2bfa8cdcfb454985d50d91b2c8829df57d4365122268281a199b1111f34a` |
| `2026-10-11-native-query-corrections-adoption-pre-action.json` | `e938ba8f79fd8445d14976a43c716b704f2ae32505c5960f6777b5197108d1bf` |
| `2026-10-11-native-query-corrections-adoption-result.json` | `116b223a2c567705ab2a0ea35571dd9c97f9c32c8184ba5673a065567f6019d2` |
| `2026-10-11-native-invocation-format-adoption-pre-action.json` | `65ec3430fa1b9df56a474d5ace04b8690bf75fde57051243358c329f42e5b0ba` |
| `2026-10-11-native-invocation-format-adoption-result.json` | `c207f010922853ad6a576edac9fa251c28a8c1fa9baafb7058d68724451227f8` |
| `2026-10-11-native-runtime-phase-adoption-pre-action.json` | `2a5404a616859d28bbee5cdec051f16eac5bb59a4221447e7f62bb6e975397bc` |
| `2026-10-11-native-runtime-phase-adoption-result.json` | `f131a4a1d9cb7d393eb7f36f7fbf112170c30c41c4cfc364d803607ee6794411` |
| `2026-10-11-integrated-models-LC1-result.json` | `048718131930884ee5837d0b855f1d5bdca5bb41bdbba73ab8eaab55dd89406e` |
| `2026-10-11-integrated-models-DM1-result.json` | `3f8ebc42e5a57dbfe8037e0b9267810feba7e04180d1346a13e68d691770e723` |
| `2026-10-11-integrated-models-DM2-result.json` | `df65c1ce8cb83910b2068d18cfedaa9c8ad902df8ba7fb82c9ce428308e4e95b` |
| `2026-10-11-integrated-models-QD4-result.json` | `6014ec4b1249ba2f86bfe240ab50391d2b203aeb26445dcd6f639905191759ab` |
| `2026-10-11-integrated-models-NM1-result.json` | `943403697f3862f25a3dcbb8889bb48f421d287ba4619a92ee95eec3bdcf9ba0` |
| `2026-10-11-integrated-models-RQM1-result.json` | `330306f2b93377a07b9a089b3f511b09a644f5a6ca80f9ab0b496085910857d0` |
| `2026-10-11-NM1-analysis-stall-diagnosis.json` | `3c5418992ffc944b1940bf26af2d5418cff2ddbca5e48ba2e07b7b3329f4c910` |
| `2026-10-11-NM1-owned-resource-sample.json` | `681362b68a9c97878268f6d7d364cc8765e69c34413291c14c881824281e5cce` |
| `2026-10-11-NM1-owned-Java-diagnostic-result.json` | `f1d06d536714e1a179276c18a2d7fd8887d65106e8ae67a4421c7494cb0aeb7d` |
| `2026-10-10-integrated-models-NV3-result.json` | `7f267868baf0279559ecf20291097c2e0f12bc69bb207588c78a0baf874ca6da` |

| Original execution receipt | SHA256 |
| --- | --- |
| LC1 | `f64ab33fb1f1656f6d94d27ff91756ee791982874e9271bf118f9bbea973fc3e` |
| DM1 | `e697606c785def6025d5665cff77dc9af99d9b4859a0be920905340a2f95a52e` |
| DM2 | `e0e7a222d5b9a5f50a0587417f339152eb5b7c1ebcc4a3f316c1376ef9fa0cc4` |
| QD4 | `2545ffbdd37cf98f7ef3fb6ff93fe2b796f4764cdec4aabeefd43ee59b5b7e95` |
| NM1 | `1807cd5b955159915ad3f28b44ee1d142907f83a1ed2497eabb3cfab4650a64e` |
| RQM1 | `7cb51727cf2fb539882fd754491a5cdc0b7058df265dae57b1242fa2556a161c` |

RQM1 compiled/linked C-bridge evidence is at `/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/5cfd50d3-59b7-4578-ba4a-4378cba82717/workload.log`, SHA256 `9587fb55c5a43d8b03b798ec1e4787c7c58256f9e6f25c1f90487fb00e9a02e4` (lines61–67). NM1's copied owned workload log is at `/home/jess/.local/state/omux-proposals-20261010/root/docs/agent-notes/2026-10-11-NM1-owned-workload-log.txt`, SHA256 `780ba8335c043bca3b02711b11e87f9236b66bd69c3b20baa74475e679003192`; the diagnosis binds its terminal analysis progress. No model, source flag or documentation classification substitutes for native live proof.


## Root terminal vault continuation — 2026-10-11 03:24 UTC

The frozen checkpoint's pending NV4 observation is now terminal. On exact b40 source, NV4 epoch 8e0e13c4-0f4e-4c10-a88d-b869987ff57e completed **0/0**: the current user's normal default Secret Service collection exists and is **Locked**, with matching identity in both observations. No Unlock/Prompt, factor, item, key, Omux-datastore or provider access occurred. Generic cleanup remains empty/unproved, readbacks0; original cgroup absence supplies no ownership qualification.

Original execution receipt SHA256 is 0285dce2bb23bed71c0d4053f941952fcc94dc52ec653bb71a13c04d893bafff; metadata SHA256 is ab1e7bf787e0a058694fe62c2c17b611e020150cfb3a00a4826eb7a4fa1df1af. The result 2026-10-11-integrated-models-NV4-result.json under the absolute root above has SHA256 9967c4a05fb3e03607431ef50e47e4b1142dcf6cdfc7ef90d240787ed827434f, recorded at 2026-10-11T03:24:29.254209Z. This fresh collection observation supersedes the pending status, while retaining NV3's original evidence. It reads no account count and proves neither loaded resident custody nor two-account enrollment. The normal OS unlock/restoration prerequisite remains open.


## Root implementation and terminal proof continuation — 2026-10-11

This continuation supersedes pending execution status above without changing the original checkpoint or its failures. Current implementation source is `233c122b82f19a42d07e3590b5432fc019709079`, parent `e0e914ccaefec7b94d695c2db714bad27c0caff0`, tree `f9a66f428a68a6ddb861317a990a62a3b03ea2bc`, declared graph SHA256 `c778b81971686a1aa7f77270c6ebd6b4af9acd283f5229136272ec40810d1fe3` /432 files. Commits were pushed without force; the original mixed index and nine protected helpers remained unchanged.

The genuine metadata producer's unused delivery dependencies were removed at `67fa270e8bf8c94d7422c1100f37a753e1a6dfc1`. IM1 then genuinely failed its new source-closure fixture: an imported function became an instance-bound method, and an exact existing deferred `pack` import was omitted from the fixture's classification. The correction at e0 uses `staticmethod` and the explicit existing import tuple. It does not relax production verification or ignore imports broadly. Original IM1 exits **3/3** remain; corrected IM2 passes its five source-closure models **0/0**.

At 233, verified account enrollment refreshes supplied descriptive account type; omission retains the existing type and new accounts default to generic. Identity/source/tenant/tombstone gates remain before mutation; allocations are staged before changing the source association and type. This confers no quota, entitlement, grant, renewal or native-session authority. Four meaningful regressions cover held native work and omission, refusal fences, allocation failures, and the encrypted import/replay-refusal/restart path.

The same successor isolates SDK export from exactly two unused delivery modules. All SDK leaf inputs, declared data, byte/NAR/lineage verification and original deadlines remain. SDK export still regenerates metadata inside its own original 600-second phase. Source isolation is not metadata-output reuse, a qualified SDK, a measured speedup or a timeout diagnosis.

| Terminal gate / exact epoch | Source | Actual result | Cleanup scope |
| --- | --- | --- | --- |
| IM1 `b1e107e7-ae20-4f54-95ba-333353ac3b30` | 67fa270e | Metadata23 and docs PASS; source-closure fixture FAILED with one failure and fifteen errors. Original **3/3** retained. | Generic empty/unproved, readbacks0. |
| IM2 `750f875d-dfab-44a5-8e1f-b2b171719fb1` | e0e914cc | Corrected source-closure five models PASS; **0/0**. | Generic empty/unproved, readbacks0. |
| NM2 `e9af2ab5-1131-4f53-954b-5973ee5296db` | e0e914cc | Genuine metadata producer FAILED at original analysis deadline; **125/124**, 114 packages /56121 targets configured. Zero tests and zero metadata outputs; no selector admitted. | Exact owned stop; **two** verified cleanup readbacks. |
| IM3 `90998832-c4e3-4e20-b121-1655cd8519b3` | 233c122b | Domain53, snapshot-import15, source-closure7, SDK/metadata23 models and format PASS; all five declared targets **0/0**. These are model/regression predicates, including encrypted persistence, rather than installed/live proof. | Generic empty/unproved, readbacks0. |

NM2 completed before 233 was adopted. Its terminal SDK repository observation retained 60569 aliases, without repository BUILD or metadata JSON publication. Earlier samples showed partial alias materialization and bounded resources. Those observations locate unfinished declaration work; they do not identify a complete root cause. No unchanged NM3, SDK export, final compiler dispatch or budget increase was admitted.

The next native implementation candidate is a Bazel-invoked locked-Python repository declaration helper. The source-only boundary review remains a finding, with no implemented helper or performance result: it must preserve every leaf input, physical/link/absence checks, retained-root and external-target invalidation, top-level metadata contracts, failure publication and all downstream action authentication. Complete watches and partial-repository rejection require independent qualification before another genuine attempt.

The metadata/SDK/compiler/runtime/ordinary-TUI selectors remain unqualified; compiler7/8 stays HOLD. NV4 remains the latest normal default collection observation: **Locked**, metadata-only, no fresh account-count or loaded resident-custody observation. Normal two-account custody, renewal adoption, actual Codex package, ordinary native resume and same-process handoff remain open. Installed browser consent/provider acquisition, current fleet activation/update/removal, Darwin, signing and deployed successor downloads also remain open. The original fifteen-hour goal stays active, overdue and incomplete.

The completed source-only documentation readback found all four earlier authority corrections already present at e0; no duplicate patch was adopted. Linear's seven own comments and PR541 received an exact-readback factual checkpoint while NM2 was live. A final terminal reconciliation follows this appended note; no issue acceptance, scope, completion state or historical proof is promoted by a comment.


| Added durable artifact | SHA256 |
| --- | --- |
| `/home/jess/.local/state/omux-proposals-20261010/root/docs/agent-notes/2026-10-11-integrated-models-IM1-result.json` | `469baf49bc9daa7928adb8f630671ba0fe54e5607b4ae198dd3878713b10e9b2` |
| `/home/jess/.local/state/omux-proposals-20261010/root/docs/agent-notes/2026-10-11-integrated-models-IM2-result.json` | `9e7ac8498be1c48830d6d55bed6db8903cd9f6aa8c0a4382e20c2c9fdc9626de` |
| `/home/jess/.local/state/omux-proposals-20261010/root/docs/agent-notes/2026-10-11-integrated-models-NM2-result.json` | `0a251bcf6b0e2a79d309415c9b82c275d603bf5b2ecbc2d4000ce3d3ceea77a7` |
| `/home/jess/.local/state/omux-proposals-20261010/root/docs/agent-notes/2026-10-11-integrated-models-IM3-result.json` | `ece9b612aa48ea50305d1c23886e9651869b9f4a9a076b7a1c820729b982b265` |
| `/home/jess/.local/state/omux-proposals-20261010/root/docs/agent-notes/2026-10-11-NM2-terminal-declaration-observation.json` | `4b7bb3fde8c89fec3e7612eeecc771ed554ba3b2551487d035d184ab15d31082` |
| `/home/jess/.local/state/omux-proposals-20261010/root/docs/agent-notes/2026-10-11-account-metadata-sdk-isolation-adoption-result.json` | `824df8dd5dcef8ccc5dd279ea274822744ae155cfb805d963cf7267ec2e211ac` |
| `/home/jess/.local/state/omux-proposals-20261010/estate_home_manager/docs/agent-notes/2026-10-11-native-metadata-repository-boundary-review.md` | `3ec274a5ddd815351bda4b5ffa580d5a5dd46047c40b522e709b7f0032b06beb` |
| `/home/jess/.local/state/omux-proposals-20261010/estate_docs_authority/docs/agent-notes/2026-10-11-docs-authority-e0e914cc-no-change-readback.txt` | `d4798df4feda45ff5eaa1ab81f9e7ee928a3b2fdbfca15686680e00c0eb7777a` |
| `/home/jess/.local/state/omux-proposals-20261010/root/docs/agent-notes/2026-10-11-estate-tracker-reconciliation-v3-live-result.json` | `3d2203b50758c87ad02ec9808eca05bb0640df8902e5f809676d6ab8428e39c9` |
