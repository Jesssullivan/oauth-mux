# Native peer and durable lifecycle implementation checkpoint

Authority: user integrated installation/lifecycle goal; AGENTS.md and R-HOOK-CONVERGENCE-20261004/R-N13. Root owns adoption and execution; independent source reviews qualify the exact packets. The original October 5 goal, checkpoints and full acceptance scope remain intact and incomplete.

This implements the Omux-owned application adapter direction in [the active reset](../plans/omux-native-account-lifecycle-reset-2026-10-02.md) and [native adapter contract](../spec/native-adapter-contract.md). No vendor-supplied Omux hook is a dependency. Ordinary application launch/resume and same-process handoff remain required product outcomes.

## Implemented source

- BUILD.bazel and src/platform/native_peer_runtime_bridge.c declare an opaque shared C ABI over the production peer verifier. It owns duplicated socket/image descriptors and the original peer pidfd, checks the actual main executable around authenticated descriptor receipt, and closes refused rights.
- tools/codex_native_acquisition_peer.py serializes bridge access, validates the declared shared-object bytes, retains image/socket identity, and enforces one fixed exchange cutoff after polling, native receipt and final peer recheck. tools/codex_native_acquisition_runtime_qualification.py joins genuine compiler material before peer capture. Its top-level runtime registration remains unavailable until the package/closure and direct native launch/resume authorities are implemented and proved.
- src/reliability.zig and src/engine.zig derive phase outcomes from the existing durable recorder, separating success/refusal/failure/cancellation populations and their timing. Supported demand/readiness remain unknown. Source detachment measures daemon-local handling before the final terminal snapshot commit; it does not claim full user elapsed time or provider waiting. Poisoned custody suppresses derived outcome authority while retaining raw diagnostics.
- Engine tests keep privacy and deadline assertions strict: an intentionally empty public native path is inspected as a JSON string, the existing native deadline error is expected, and manually constructed fixtures release their own state-directory and SQLite allocations.

Source packets: peer bridge0e2fab875a28ae640bb512f7fa2e39b84e119b8ad0bc5b11fed42c593344fc8e (review069a0fcd11a9de86917711ce913669f0a8f01ab06f660b2963502ded505f08b0); lifecyclea37f00dd968f07eccbcd9ac550efda31a6ffa980724ab0f17cf40a77dd180538 (reviewdaff0ae8f651d53746a6aba4a26bb3629b2f9e98c5216414ddb8ba213461b87e); fixture98e0e0400eca2ac961e0f3c605b35c41b7c2de18ce0b12ad4c7ee9b70ebc0f20 (review18eef6d809361fccd6eac9257c8d222e2d89e58c07537e627d6d3c85765b8677). Frozen proposals/full views remain under the operator's owned Omux proposal directory; the Engine hunks compose without changing production deadline propagation.

## Existing evidence and required next proof

At c5116c45d2f42bf43283bb18b8b3aa45a3d5232f, actual NU4 da39eb62-b233-4053-96b7-3909d8e2f7b6 compiled all ten targets: nine passed, Engine failed two assertions and three fixture leak checks. Preserve original receipt52827994ebe75bb06dccff46c1166fd05a6366168ea19dc8c95daa03f3defca0 and all20 copied evidence files. The current changes do not retroactively pass NU4.

Actual NB1 0e6f6242-a2dc-4909-ad8c-6a8a02d9a704 stopped in analysis: the input repository read a filegroup label basename rather than the configuration JSON. No binding producer ran. Original receiptfb23e2adf3e3c06418d901ab85122642944c0917a789ee3f45fbf9de3d52d22e and workload diagnostics remain retained. Both executions completed owned empty cleanup twice, with absent original cgroups. MODULE.bazel now selects the exact exported native-acquisition-inputs.json file, retaining the target data filegroup. Exact correction4f198a14f839c8fffd0bc5658cd2f6697ecb1a1821c9871a94aa953b71f8fc48 received independent source review78f0c1bca360beacc15cd47ffced14a83afaa21474434b86d31af64aea8c2a53. The genuine binder must be rerun on this new clean commit.

The new peer test source adds nine methods to the existing eight runtime models; all17 are unrun at this source-adoption checkpoint. Engine and dedicated reliability lifecycle tests must validate the new accounting, followed by daemon/Home Manager wiring and actual installed work. All project executions remain through locked Nix/Bazel with one contained coordinator, unchanged resource caps/deadlines and Rust ledger7/8.

The [reliability objectives](../reliability/service-objectives.md), [support/completeness contract](../product/support-and-completeness.md), [user stories](../product/user-stories.md) and [repo roles](../governance/repository-roles.md) remain authoritative. Counters are not an achieved SLO, contractual SLA or staffed support promise.

Traceability: [TIN-2063](https://linear.app/tinyland/issue/TIN-2063) (installation/lifecycle), [TIN-5338](https://linear.app/tinyland/issue/TIN-5338) and [TIN-5421](https://linear.app/tinyland/issue/TIN-5421) (exact candidate/native proof), [TIN-2057](https://linear.app/tinyland/issue/TIN-2057) (full continuity acceptance); review PR541 https://github.com/Jesssullivan/oauth-mux/pull/541 remains draft. Normal OS-vault custody, durable live enrollment, ordinary native resume, accepted-history preservation, same-process live handoff, Yoga human browser consent and Darwin support remain unproved. PZM/GF stays held.


## Direct-main custody implementation and actual NU5 checkpoint

Actual NU5 f805032a-6234-4bd4-9f47-da6d85a7ea10 at d6ffffe compiled all ten targets: eight passed; docs_check lacked this note's classification and Engine passed281/282 with one malformed diagnostic-request fixture. Original receipt51c74f2188a92189e611270c53fc8b9cfd04e6acff679c3aab5e7139e738777b,20 rehashed copied evidence files/143698bytes, workload3/outer125 and original owned empty cleanup twice are preserved. This source correction does not retroactively pass NU5.

The classification now includes this exact current unshipped note. Two test RPC parameters use explicit null instead of an empty tuple serialized as an array; production admission and custody are unchanged. Fixture packet9a86dc6b6505bd471fca72149c4c29c5bb18686e70b6592e783180b121c8f19c and classification49d0b4731946df846a4cbebcb62f852aa1f432c96c364169bf901d367d0fb4fd have independent source reviews.

The composed runtime v3-to-v4 source adds genuine compiler/package-evidence joins, bounded full canonical NAR closure reads, retained raw main and interpreter descriptors, and a direct app-server qualification child held behind GO until its original pidfd is captured. The C peer bridge also compares the authenticated peer pidfd with that exact child. Failed or expired cleanup retains the original pidfd until confirmed reap; retry keeps the original deadline, and cleanup failure preserves the primary launch exception. Source review790742b1b05f038c5bb843ba9d56837b60bcb405966b08ac429322f4e7c82e72 qualifies only this corrected composition; historical v3 BLOCK remains unchanged.

The existing runtime model target now collects32 methods, including15 process helpers; these remain unrun. App-server helper ownership does not prove ordinary TUI launch/resume. Main configuration, actual candidate package/runtime closure, browser consent, native acquisition and live continuity remain unproved and unavailable until their genuine evidence joins succeed.

The exact additive resident-lifecycle-accounting-models-reserved cohort invokes the guard regression, the seven standalone durable recorder tests and docs_check. It reuses the existing coordinator, locked inputs, original1200-second deadline, unchanged worker/resident caps and Rust7/8 ledger. Those tests remain unrun; no achieved SLO, SLA or installed proof is claimed.


## Actual lifecycle validation and binding-validator repair

At 07f6474, actual NL1 31d0821c-f8fd-4dd1-9178-047ac6f7e3cb passed the exact three-target recorder/guard/docs cohort, with workload/outer0/0. The guard ran14 Python methods; the Zig target ran17 tests including seven dedicated lifecycle tests. Original receipt3dff07081e24e2d4403fc1003ba54ce7fbc0412e47d07eb905c746417502ea9a and six copied/rehashed evidence files/6165bytes, manifest390ac8c5fc7297de9a0d351945551ed83846cda9412887f83a5795687fc5d5d2, remain retained. Original descendants were empty, owned cleanup was empty twice and the original cgroup is absent. This establishes the stated durable-recorder and admission predicates; measured user baselines and achieved SLO/SLA remain absent.

Actual NB2 707d1e72-cc92-443d-829f-1d86fdf2826a reached the genuine binding action, which refused its input. Original receipt8e19d92f8e5e77054b4a2d3ecdc0542a37f4dd9e8bbbc18bce8b6f737503370d and two copied/rehashed evidence files/929bytes, manifest496c93a2f1e35e74ad08e2f3fc6894bb18af937d8ee9f19b48d8f143a218365f, preserve workload3/outer125 and its original owned cleanup. No binding output was selected. Its sole coarse refusal does not identify a first failing predicate.

Source review found two unconditional validator obstructions: strict require accepts literalTrue while a successful regex returns a Match object. Both existing expressions now use explicit is-not-None without changing patterns, scope, source/graph/guardian/cleanup/caps/clock or evidence joins. Five real producer_success fixtures cover physical JSON/evidence hashes, successful complete cohort joins and malformed namespace/leaf/policy/evidence/XML refusals. Exact patchd01c432a9dfa52b32f89cdbe27494ad5f8ef8d64669ee64c0fb2c71d40c8e06e received independent source reviewb75c9ec6971ec46d2b084c070df0a5452acbe888f840c2c12aed0a750faa7851. The new models and corrected real binding execution remain unrun at this source checkpoint. No historical NB2 RCA or retroactive pass is claimed.

User-requested cleanup removed inactive NU5/NB2 output caches after original terminal ownership and copied evidence checks. Receipts, workload logs and all22 copied evidence files remain intact; genuine source/SDK inputs, current source, credentials and native history were preserved. These cache removals do not change original proof or product completion gates.

Required next actions remain genuine binding, real metadata/SDK/plan/query material, compiler/package/runtime qualification, ordinary native launch/resume and live same-process handoff. Candidate app-server models alone never establish ordinary TUI support. All new runtime, installed-browser and real-account claims retain their independent gates.


## NB3 terminal failure and linear source proof implementation

Actual NB3 d20dbf1a-7649-4c22-884b-5ad635bc0db8 at a47d243 reached the genuine binding action. It wrote an initial4655-byte binding artifact (SHA506e05870f323c7c148bc50c99b7f2422db39f669c460074e0770f67a1329a84), then failed terminal revalidation within the original clock. Original receipt60e42a863fda8982ecf3c753ba3763a471a15927bfd951a3b51a21768b902b6b preserves outer125/workload124, cleanup-unproved, descendants-empty false and test evidence not-admitted. No artifact is selected. Separate same-original-unit readbacks later show MainPID0, terminal original supervisor and absent original cgroup; those observations do not retroactively qualify original cleanup or evidence.

Source inspection identifies sixteen repeated P3/N1 reconstructions across the old producer's two binds. This is a source-derived call count, not exclusive historical RCA or a measured timing result. The binding session now reconstructs the exact third/fourth/fifth/sixth/seventh/virtual-eighth/ninth chain once through the existing transformations and receipt constructors. It holds all five actual root/tree/receipt witnesses and performs complete initial/final file, mode, symlink, receipt, configuration, patch and original guardian/evidence readbacks under the unchanged original deadline. Downstream verified-source consumers use the same session. Partial publication remains unqualified until terminal readback and the final seal.

Exact two-path patch5b44eedadca40489d06da5f8e6d5ff566c1d311a709e242f38edc787ebcdf542 received independent source reviewcc02d3f8346b4098fdb215558fbaf4396be1eccb9eb9b9a235d4ea7ed97f0415. Seven physical mutation/identity/deadline/partial-publication/closed-diagnostic models are added to the existing metadata/SDK model target, with synthetic external-lineage seams explicitly distinguished from genuine proof. All seven remain UNRUN at source adoption; no speed, SDK, compiler, installed application, ordinary resume or live handoff claim follows.

Worker/resident caps, original1200-second coordinator clock and30-second cleanup reserve, exact vectors and native compiler ledger7/8 HOLD remain unchanged. The next actual checks are the admitted model cohort and then genuine binding. Metadata/SDK/plan/query/compilation/package/runtime and ordinary native launch/resume retain independent gates. Source-reviewed main/process/bridge and Yoga proposals remain separate, unadopted compositions until their complete interfaces and custody pass review.

User cache cleanup also removed three terminal pure-unit FAST output bases; all98 copied evidence files and their original receipts/logs were rehashed unchanged. Eight planned bases remain present, with one possibly partially purged when the exact owned administrative cleaner was stopped after capacity recovered and XFS metadata IO became contended. Selected genuine source/browser/SDK inputs, source, credentials and native history were excluded. Concurrent Lab cleanup contributes to available capacity; no exclusive reclaimed-byte claim is made.


## Verified NM6, genuine NB4 selection and native runtime implementation

At exact source c35bfba68469374618c1b8fe89af7df8bbd5bbf8, actual NM6 30795c27-63a2-4d6f-91a8-b3b6261a9b2b passed all nine declared targets: 115 Python methods plus the documentation check. Raw guardian SHA5f8b3101d513a2a5b2876a1716ff7459e85ab7dc5bead8f110c732ebc9bf1972; copied evidence manifest SHAff37ad38164ae7ec673afcbc98df031daba78dde7733b11c12b75a23512fb5ac, 18 files/9489 bytes. Original outer/workload0/0, verified empty cleanup with two readbacks and absent original cgroup qualify only that declared model scope, including the seven new linear source-session predicates and earlier physical material identity fixtures.

Actual NB4 afddd8a5-0e26-4483-87ab-601d81f19c2c passed the genuine source binding action in18.6seconds, with original outer/workload0/0 and verified empty cleanup/two readbacks/absent original cgroup. Raw guardian SHA0b932a23f115fbc9f8076aff17b6531355813db5a8d220debc8c12af4580710b; copied evidence manifest SHAef7638dc7b44b5341b08a315742e0e6718d6a63d25b7b03b602eb99ed8f6d09a,3files/885bytes. The actual sealed4655-byte output SHA506e05870f323c7c148bc50c99b7f2422db39f669c460074e0770f67a1329a84 is selected literally in integrations/codex-upstream/native-acquisition-inputs.json with its NB4 path and original successful guardian. Metadata, SDK and compiler selections remain null. The same-content initial NB3 artifact remains unqualified and unselected; successful NB4 does not repair NB3's original timeout or unproved cleanup.

The reviewed eighteen-path runtime composition SHA48f1be196c0d4ab9d1040fb2217843debad3ee6ebfcb6192cb47f0457ae21ac7 (independent review SHA78946c9e511ee1b3441fab1e0679c6edb4032fa8ace92ca6d9bb56a0ff731f92) is now implemented. It joins authenticated packet-only native peer receive and held child identity, original work/cleanup clocks, isolated CODEX_HOME, real bridge/material/NAR/loader authority and selected native protocol evaluation. Each failed close is propagated; numeric descriptors are consumed once after confirmed reap. The runtime selection in integrations/codex-upstream/native-acquisition-runtime-inputs.json remains explicitly unconfigured until genuine compiler, package and bridge outputs qualify.

The composed runtime/bridge models and actual bridge production/loading are UNRUN at this source adoption. Prior NM6 results are version-bound to c35; they do not prove the new composition. Future protocol evaluation deliberately distinguishes the compiler-native-cli from an installed package primary, ordinary TUI or native resume. No provider evaluation, credential enrollment, live handoff, installed support, SLA or achieved SLO follows from binding success or this implementation. Worker3.75GiB/480tasks/190%CPU, resident256MiB/32tasks/10%, zero swap, original1200-second envelope and30-second cleanup reserve remain unchanged; Rust ledger stays7/8 HOLD.

Next required evidence remains the composed model/material checks, genuine same-source plan/query and metadata/SDK outputs, final cold compiler fit, package/runtime, ordinary CLI/TUI native state/resume, installed Chromium consent and live same-process handoff. Yoga's separate full composition remains blocked on actual guardian custody across launcher exit. The original fifteen-hour scope, clock and acceptance gates are unchanged.


## BM1 composed model result and physical fixture correction

Actual BM1 ccff4519-ba67-4d2b-8ce7-6e3bff947ead on d9b01b4 ended original outer125/workload3 with verified empty cleanup/two readbacks and absent original cgroup. Raw receipt9bb1772d8ae01563ff9d49af7913051db879b32b1f4de73e7113d020d4967ad4; copied evidence manifest04aa827d617601da24568265ac9812640778dbea9b4624e9e4e3f9dc4d3a53cc,8 rehashed files/7050bytes. Runtime qualification60methods and guard6methods passed; docs passed. Bridge material ran10methods with one failed fixture. The original batch remains failed.

The physical rename fixture incorrectly required the full original inode metadata, including ctime, to stay identical after rename. Actual Linux rename changed ctime. The corrected fixture checks retained device/inode identity and compares held descriptor full current metadata against the renamed original physical path, while preserving the distinct replacement-path and late-byte-corruption assertions. Production full metadata/byte predicates are unchanged. The corrected fixture and composed batch remain UNRUN at this source adoption; no genuine bridge, native runtime, installed application or continuity claim follows.


## BM2 success and explicit package selection wiring

Actual BM2 db47082f-a923-4b7f-9e1d-2d631f90d51d on7e3ba8e passed all four composed model/docs targets:76 Python methods (guard6,bridge10,runtime60) plus docs. Original outer/workload0/0, verified empty cleanup twice and absent original cgroup. Raw receipt8eae75ecb44436000ae659ef7f28c1345e79a8a0dcdb0ac9324b3298fb71837c; copied manifestcecc4f57445fe5bebccad9f51be6bf93d57c66a4533e3b4871158cc8e82ba7e9,8 rehashed files/4252bytes. This proves the corrected model scope, not actual bridge output/loading, native runtime or ordinary resume. BM1 remains failed.

The package module extension previously always instantiated an empty selector, so the real producer could never receive qualified materials. It now consumes exactly one root-owned tracked configuration at integrations/codex-upstream/native-acquisition-package-inputs.json, with closed pending or explicitly selected material. The pending selection remains null. Actual producer checks still join twelve raw roles and five independent action authorities before package transformation; declaring a candidate selection never qualifies it.

The exact combined nine-path packet7a8d0cb251d99a17e9e9932c21e16d9e04c2980c5d55747664a5fbce09a22565 received independent source review080bdae3bbdd0daebb6e8c28658eaa708b37c1ec0eaa28967644bf694913be68. A distinct native-acquisition-package-models-reserved profile admits only the existing guard model target, production Starlark receipt-scope/selector analysis target and docs check. Existing vectors/caps/clocks remain unchanged. Twelve selector declaration cases and two guard admission/clock/projection cases are added; actual analysis and models remain UNRUN at this adoption.

The required next stage order explicitly includes genuine same-source native_flake_seed_plan_qualification and codex_query_registration_reserved_producer, a literal verified public query-tools selection and the descriptor check before native metadata/SDK production. MODULE's query-tools repository is still unconfigured; no future plan/registration/metadata/SDK/compiler/package pins are invented. The ordinary TUI direct-package reader remains a separate implementation lane. Original full goal and product acceptance, native history/no-replay and external renewal ownership remain unchanged.


## PM1 actual declaration failure and Starlark syntax correction

Actual PM1 c1b8dc1d-c812-474e-9481-d30dd4ede4f0 on31800c3 ended original outer125/workload1 with verified empty cleanup/two readbacks and absent original cgroup. Raw receipt04283ded260d358caa8ad04e72cafc95df43240c23e404d85fef32ae636f2a87; preserved evidence manifestf6cf205241fa8ca4360ce788056ae21fd08002a41b961d5dd66ab68c7be7ceba records zero copied test files. No tests ran: loading the existing package reader through the new selector analysis revealed an older Python-style chained comparison, which Starlark rejects.

The package member positive-size/upper-byte-bound expression is now written as two separate comparisons with the same conjunction and exact limits. Declaration, selected material authority, input paths, caps and clocks are unchanged. Corrected analysis remains UNRUN at this source adoption. PM1 is still failed and supplies no guard, selector or documentation pass.

## Actual PM2 / NU6 verification and installed-delivery implementation

Actual PM2 d27ed2f5-c515-4390-b97a-1864df6730cc on e2b5f7a passed the exact guard/package-selector-analysis/docs cohort. Original outer/workload zero, empty owned cleanup twice and absent cgroup. Receipt c1007b50da2907bea3d39c55e0adc2618772bb4d7283ae126c5b77a9375d6266; manifest c778e1eb5f17912a19f53da996a8edc93be53046f9ee149e3a6c217b76903272, six rehashed files / 2887 bytes. This validates the declaration fix; PM1 remains failed.

Actual NU6 e7e9422b-349b-41b3-92c2-1eacee709fd4 on e2b5f7a passed all ten exact Engine/native-acquisition/delivery unit targets: 612 Zig cases across six targets, 26 Python methods across three targets and docs. Original outer/workload zero, controller failure absent, empty owned cleanup twice and absent cgroup. Receipt 3ce1efa6ae95e203845cb3d78279bd657687d8bf18612421d759eff3f0406db0; manifest bdd9be4ebfee738f0f09178e27a74909d38a57f5cdcd7d27d4e6bbc0e94a5ef1, twenty rehashed files / 143602 bytes. NU4/NU5 failures remain preserved and version-bound.

Actual QP1 da53414f-6747-4d23-b620-53fa906e3446 on e2b5f7a failed at original-byte-readback with the combined nar-bound-or-deadline diagnostic. The diagnostic does not distinguish the bound from expiry. Original outer125/workload3, verified empty cleanup twice and absent cgroup; receipt08002ad42ebd862465c00d1aa7c0a26c9492a20cf498c6933667cb6fa75560ee, manifest8d08e99c8e6c29641feec77c8ffa22b5dbb41caed10e03e4a09b04351f201e0d, two rehashed files /1163 bytes. No matching successful plan/query selection exists yet.

The independently reviewed 29-path source union3b772c8c195141e889cc4793a8b3e1af3777c2b130eff9287f5c6a606a2e9bb7 (reviewa0e2c7e5f0e19683c973ea3b47a45ddb37a365e9242b65137e8459fc12b5eeba) now joins:
- tracked Home Manager bundle selection, bounded reconstruction/evaluation profiles and post-custody deadline fences;
- exact digest-addressed compiler-ledger snapshot admission, confined to that role;
- a distinct genuine-package ordinary-TUI proof lane, preserving native rollout bytes and observing /export, /rename, ordinary cold resume and installed-primary identity;
- future invocation cleanup readback fixes, without retroactively qualifying NB3.

Pending bundle and ordinary-package selections stay null. Home Manager still owns declarative files and registration. Current Omux artifact production-to-HM evaluation remains a separate implementation task; the retained legacy artifact is not current-source installed proof. The ordinary fixture crosses its isolated private bus with declared runfiles and original clocks only. It proves no native support, live handoff or accepted-history behavior before real package and installed proof.

The disjoint two-path reserved-clock correction43ba887b6123f86fa4fda48cad1e86db5d9b8df70c2cc31a3fffdb03697d3344 (review362b0eb0aff326b4a2cf4e1d04e30439f73acb8335e4bbe3ae03b37f6508afe6) uses the existing reserved test ceiling and original root remainder, retaining both private and outer cleanup reserves. The nonreserved 600-second limit, original 1200-second root, resource caps and protected nine helpers are unchanged. No NAR or byte verification is bypassed.

All newly integrated models and actual source-specific producers are UNRUN at this adoption. Next is exact declared model verification, a fresh same-source QP2/query pair, metadata/SDK/cold compiler fit, genuine package/runtime and actual ordinary launch/resume. Rust compiler ledger remains7/8 HOLD. Yoga guardian composition, human toolbar consent, OS-vault enrollment, same-process live handoff and Darwin remain independent unpassed gates. These sources implement the full goal direction and do not reduce its scope, reset its original checkpoints, or establish an achieved SLO/SLA.

## Verified integrated models and current artifact / Yoga implementation

On e38e9b3, IC1 9ad5fa44 passed the exact four-target clock/cleanup/carrier/docs cohort:190 Python methods, original0/0 and owned empty cleanup twice; receipte0cfb37d33ddb9a75164221113c4e58b07d5d5bc5379ced7a3f123a01c85bc6f, manifestef7fe22d29b540a8c314e65be3d4aa3604247da4b759192489a680982eabca3c,8files/4286bytes. IO1 6eea060f passed the exact ordinary-TUI model/docs cohort:27 Python methods, original0/0 and owned empty cleanup twice; receiptfc0cb09adb22894c1c4b6826656ac83e320a8a486e148b30df45e90654c0c2fe, manifest632a8be157b955700bb9fb585d54c5394f191f23524d2a9d73ce9f19bf883b17,8files/4036bytes. IH1 af4e7712 passed the three compact-HM guard/selector/bundle targets:52 Python methods and declared Starlark selector cases, original0/0 and owned empty cleanup twice; receiptb2aedaa407afd0464adba3c57156d65fd8940649703c347d43039b467f499f35, manifest6722d4999e464dfeffc1bac4952b830bb7caeffcfa9f62a89633cd0a87f1bc5b,6files/2911bytes. All three original cgroups are absent. These scopes are model verification, not installed readiness.

The exact39-path current artifact/Yoga unionc416d64d5578ca14a492fb46b5e9480fb3b56781a591a5dd306bfe9c399d0ea4 received independent composition reviewc04d95c0fb9fc973484d3d8edee2d618bb8f4182ac92cd4be4ad6a2428b3a71b and lineage review9decf863634919103b51ae26555ae3c6c2424c27e4efe4ee232b453b19a29168. The component reviews preserve the HM900a deadline HOLD and Yoga3946 final-caller BLOCK as historical findings.

Current Omux artifact production now has a declared target and guarded selection that joins the actual original guardian, source/graph, successful test log/XML, archive metadata and full NAR inventory. The new versioned Home Manager consumer selects that current artifact separately from the retained legacy archive, reuses independently qualified bundle sources and keeps the original admission/cleanup deadlines. The current selection is null until a real producer succeeds. CLI, daemon, native host, thin UI and extension delivery facts remain Bazel-derived; schema presence is not installation.

Yoga installed preparation now uses the original direct guardian and exactly one console worker/pidfd, with actual scope identity/caps before Go, bounded nonblocking reaping and one shared cleanup cutoff through final parent and preparer readbacks/releases. Persistent operation metadata confers neither execution nor cleanup authority. After its own exit, the Python guardian is gone; only an actually registered bounded OS scope can retain control. Host manager policy, scope escape/lifecycle cleanup, installed image qualification and human toolbar consent remain unproved. The conditional HTTP declaration pin matches the exact new MODULE bytes; no HTTP table or lock changed.

All newly integrated current-artifact/Yoga models, producers, evaluation and installed gates are UNRUN at this adoption. Existing source models keep their e38 scope. No protected helper/cap/root clock/compiler-ledger change or goal-scope reduction occurred.

Source audit of the ordinary-TUI critical path confirms that SDK export generates and authenticates its sibling metadata in the same action. Standalone metadata is optional diagnostic work, not a code prerequisite. After actual same-source QP2/query registration and the genuine public query-tools selection, the admitted descriptor singleton is //tools:codex_metadata_query_tools_descriptor_test, then SDK, native plan/query, measured final compiler fit, full package and ordinary TUI. No retained qualified modern compiler output meets the current ninth-source joins; ledger7/8 remains HOLD. Bridge qualification remains an independent runtime/continuity gate, not an ordinary-TUI package prerequisite.

Fresh OS-vault observation is queued through the existing resident-enrollment Bazel metadata target, with unlock:false and no item/key/factor/database/provider access. Its result can establish the sampled collection lock state only; it cannot establish installed daemon wrapping-key custody. Last installed and OS observations retain their original source/time scope. Full goal remains active, overdue and incomplete; native resume, live accepted history/handoff, current HM activation, human browser consent and Darwin remain open.

## Actual V1 / IA1 failures and narrow corrective implementation

The explicit urgent local cache cleanup completed without deleting source, credentials, native history, qualified artifacts or retained evidence; live build caches and the Nix store were retained. Final capacity readback is in the root receipt 2026-10-10-local-cache-cleanup-final-readback.json. Capacity is shared with other lab work and is not a private reclaimed-byte claim.

Actual V1 ecc0bef8-6e35-4868-bce4-2e34aef3b526 on049654b failed with original outer/workload36 before the standard OS-vault observer ran. Bazel attempted to chmod the existing implicit shared HOME user-root symlink and refused. Raw receipt3ca7cf594ed70cc53d722ecfd340e009e6ca6206810406300abe1b268d5a5f52, log3b3401a5305975513d34e243546fcb6fbc177bd4d3e8edf27928eae619423e49. Original cleanup is empty with ownership unproved, zero readbacks and stop not requested; descendants empty. No fresh Locked/Unlocked state, installed wrapping-key custody or provider access was established.

The independently reviewed two-path private-root repair f77e909b4bdd7d486eec4ef7c91e75a0db7c7532687016d5b9a8f7297f5abe8a (reviewd697affda538db8fa3704986454a088c430574470913a9312502de1361d654a7) gives every coordinator-built Bazel command one startup output_user_root under the existing owned run, before the verb. Caller overrides remain refused. It changes no shared cache, output-base selection, caps, original clock, finite vector or protected helper. Actual source qualification and a new observer invocation remain UNRUN at adoption; failed V1 is not promoted.

Actual IA1 dac81866-d713-43c3-a276-92b954f47f80 on049654b/427 ran the exact six current-artifact/Home Manager model targets:four passed and two failed. All46 bundle fixture setups rejected the new optional action_deadline keyword; the actual inventory fixture rejected its writable temporary root before intended late corruption. Original outer125/workload3, owned empty cleanup twice and absent cgroup; raw receipt0cf3b7ab794bc45bf2f65b44aa84ff2a24f831d5252f74666350e6dfbaef1a3a, manifest577c75b6a3d39b7ffed5097c7138e3021a797c7f5d8953aba28fb5cbcb0bc2ef,12rehashed files/519556bytes. No artifact, HM evaluation/activation or installed readiness follows.

The independently reviewed two-fixture repair a5add9c4342ccfd3d6a4e0c9a6f69485609474d31385c635df8d3f2ff9e26b75 (reviewd4268056e60cd8a39e3a7e93128be17e2068983c2d0d620d576547b66862235c) accepts the optional finite future deadline in the assembly mock before any writes; seals the real inventory root read-only, performs owned leaf corruption and restores root permissions in finally for cleanup. Production custody, byte/NAR predicates, deadlines and packaging remain unchanged. These corrected models are UNRUN at adoption; original IA1 stays failed.

Root is the sole source adopter and project executor. The original goal remains active, overdue and incomplete with its checkpoints and full acceptance intact. Rust compiler ledger remains7/8 HOLD; current artifact production, native launch/resume, normal key custody, human browser consent, accepted-history/live same-process handoff and Darwin remain independent unpassed gates.

## October 10 post-cleanup operational checkpoint

Dated authority: Root's durable `2026-10-10-post-cleanup-implementation-checkpoint.json`, recorded2026-10-10T16:08:18.442138+00:00, SHA256 `3d5d24237679cdf73a00971c58c32a7d42aa1acd6f1dacbb8edbc8ebccd0e1e4`. Pushed source726033dc768cba444eee0aeaa8f5f22ef513f995, treeeac6b7f6ee4dbeb25fb6d881abc08496d96c37e1, graphd2dcd382f98d09cacae43f8ebaa8ce00d4c51a01bcc8c801cff4e193a41ca4a6/427. This adds dated facts; earlier failures and adoption-time UNRUN statements retain their original scope.

Actual IC2 epoch29bb84f3-0275-4e03-a0c7-e3f40fa90cf6 and IA2 epoch752c8241-e499-4ba8-b934-64bd97d0c7be passed260 Python methods in aggregate plus docs_check. Both original guardian/workload exits were0/0, with verified owned empty cleanup, two readbacks and absent original cgroups. Their receipts are1c460b6db282e91f84af90ecb4ba4d379dd148f28bc28888c60a0ce564ccbe6d and467a2a5884d0530d3141b7455a15de238b6e51005022ebe6ca32896087f5dc3f. These are source-model predicates, not artifact production, installation or continuity proof.

Fresh V2 observed the normal standard Secret Service default collection as present and Locked. Original cleanup remains ownership-unproved, empty with zero readbacks and stop not requested; descendants were empty. It establishes no reserved ownership qualification, installed wrapping-key custody, unlocked authority, enrollment or credential/provider access. Actual CA1 failed with original guardian125/workload3 after all native-component builds completed. Its18.9-second test emitted only `current-home-manager-artifact-refused`; original `test.outputs` was empty. The first failed historical packaging predicate remains unknown. Raw receipt8a61f5bc6b02d5504436e24379989186d8b1dc06d695fd4c9e817f5d70799711 and copied manifest79e5b6c2d23f26af80a1f57ad4d14d4991d2b4970f7758c11993c3c816f7901e preserve two evidence files/915bytes. Cleanup was verified owned empty with two readbacks and absent original cgroup. Successful component builds and cleanup do not qualify an artifact, selected HM evaluation or installed readiness. HR1 epoch4801a753-bc88-4aaa-9610-2f9bf1fad4c0 was confirmed live when this update was prepared; its original terminal outcome remains unrecorded here.

Later explicit user authorization permits model IO without a spend cap, superseding the earlier finite-provider-budget authorization as a model-usage limit. Finite execution profiles, caps, original deadlines, retained custody and qualification predicates remain unchanged. No provider calls occurred in these checkpoint actions. Rust compiler ledger7/8 remains HOLD. Native resume, normal installed key custody, live accepted history and same-process handoff, human browser consent, current HM activation and Darwin remain unproved. The original15-hour dates, full acceptance, historical proof and active overdue incomplete goal remain intact.

## Current Home Manager source transport and Locked onboarding correction

The genuine CA2 development artifact producer passed on dc3978ca58d6418be86552e6c6b37739cc218302 (graph 7ee3591a159002765fe701ee87bac17b7207ed6289d56c0eac2f43a3e983ee4b, 427 inputs). Guardian receipt ba3ed7a7f33d2f2895b2259e39dd87f51941d48d515ac2d6e9e1cc8b1a7a7437 records 0/0 and verified owned empty cleanup/two readbacks. The 60,409,959-byte archive is version-bound and does not contain this successor. Independent read-only inspection found retained artifact 0555 modes disagree with authenticated canonical non-executable inventory entries; current consumer qualification is held for owned canonical reconstruction. Producer PASS does not qualify consumer, installation or continuity.

Reviewed pair-only V2 (232fbabdaa5e35f9a10e3004bbdb453f39a9e3452f951b8f63dac2bfae0bcadd) adds nix/home_manager_current_pair_bundle.py and its fixtures, source-only/selected repositories and //tools:home_manager_current_pair_reconstruction_producer. It separates authenticated Home Manager/Nixpkgs transport from Omux artifact authority, preserves strict legacy launcher validation and original failed HR1 evidence, and publishes only after full canonical source NAR/custody checks and owned cleanup. Current evaluation independently verifies selected source and artifact producer authority. Selectors remain pending. Conditional Yoga pin aef29844ebfbb073c55a973442c1973e1c9a23df7f7d434338b922a9290fe0d8 changes only the fixed hash to exact reviewed MODULE a30606987f378769c7762fe1ebbee28a33ba5b6db5e3e9c6b28f98c941c21785; it grants no Yoga proof.

Reviewed UI V2 d95e80eeacdee345bf2d977e0c74ef7094f9c1ea4e0c7583dc2b17cc04295df4 corrects clients/linux/tray.cpp and clients/linux/setup_ui_test.cpp. Typed custody reopen must prove available custody and loaded metadata without provider requests or handoff claims. Locked/missing/invalid-key guidance survives unavailable or malformed readiness responses; account mutations remain unavailable until verified recovery. It does not unlock the OS vault or replace a key.

New source-pair models and Qt fixtures are UNRUN at adoption; previous IA3 six-target PASS does not qualify the extended seven-target vector. Original 1200-second clock, worker/resident limits, nine native helpers and compiler ledger 7/8 HOLD remain unchanged. Installed browser consent, account enrollment, ordinary Codex resume/handoff, Darwin and measured reliability baselines remain open. Authority: user-authorized integrated implementation and R-HOOK-CONVERGENCE-20261004/R-N11/R-N12/R-N13; carriers TIN-2063, TIN-5338 and TIN-2057.


## Canonical delivery and daemon-owned timing continuation — 2026-10-10

Authority: user-authorized integrated Omux implementation; R-HOOK-CONVERGENCE-20261004,
R-N11/R-N12/R-N13. Related to TIN-2063 (installation/readiness), TIN-5338
(exact Codex adapter) and TIN-2057 (complete continuity).

The exact e7c5853/430 source passed UC1's Linux transport/setup UI targets
(cc9cdce6-955f-47d7-bb21-d80c0b88cd49, original0/0, verified empty cleanup twice).
IA4 remains failed125/work3: six targets passed, but the real wrong-family fixture
supplied a shorter header and reached truncation before the intended magic check.
The independently reviewed cf5bebb6 fixture supplies enough bytes to test the
unchanged real family refusal. It does not weaken production parsing or
retroactively qualify IA4.

CA2 retains its original dc3978c/427 artifact-producer PASS
(0980cf83-0822-48e5-8f10-c2e52e103b8c). Bazel retained its regular files0555 while
canonical inventory marks nonexecutable leaves. Canonical V3 0950587f adds a distinct
authenticated retained reader and a typed private canonical copy restoring444/555.
The full original archive, bytes, receipt, inventory and canonical NAR remain
bound; original retained files are untouched. One existing private owner/budget
covers artifact, source pair and copied modules; all newly acquired descriptors
are owned before metadata proof. Strict historical physical validators remain
unchanged. Both independent reviews are source CLEAR; eleven new models are UNRUN.

Daemon timing successor9f3e9e07 adds real authorized-handler/admission/post-original-
commit intervals and schema2 setup safe-refusal timing with separate populations.
Measurements cannot authorize another effect, repeat accepted work or count replay
as another opportunity. Historical schema1 remains readable with absent request
timing unknown. External waits, complete user latency/demand, deployed provenance
and achieved SLO remain unmeasured. The predecessor d247 shadowing BLOCK is preserved;
its two-identifier successor is independently source CLEAR. Runtime/installed tests
are UNRUN, and timing is not installation/enrollment success.

HP1 (a97f7afb-0331-4519-b1a6-8390250fddd5) remains failed125/work3 with original
receipt344a6d3b81ebc8abfbb8779633c2b6dd82a28e29a1423075704be7e0e5c67a6b,
evidence6f0f54370cd33fced6914d52317610c6c6e6fa5716fc70a04bc48bc8b36dcf35,
two copied files1259B and verified empty cleanup twice. Its real action refused
metadata/bundle-enclosing-deadline before materialization. The declared pair has
57,115 input files; cold Bazel preparation consumed1136.885 seconds, leaving less
than the required private cleanup reserve. This is no successful pair, artifact
consumer, HM evaluation/activation, browser installation or native proof.
Actual graph reduction must retain complete content digests and NAR/custody
checks; neither widened clocks/caps nor opaque source-directory aliases are adopted.

The disjoint reviewed20-path source union and current reliability documentation
are adopted only after HP1's terminal cleanup. No selector or provider production
reader is enabled. Source/graph change requires fresh exact model and runtime
receipts. The original15-hour clock and compiler7/8 HOLD remain unchanged.
Sting's normal OS vault remains Locked; Yoga's attended Wayland/browser proof,
ordinary candidate resume/live handoff, delivered adapter support and Darwin
remain separate unpassed gates.
