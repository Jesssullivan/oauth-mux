# Omux runtime and enrollment checkpoint — 2026-10-12

Authority: user-authorized integrated implementation, repository AGENTS.md,
R-HOOK-CONVERGENCE-20261004 and R-N13. The original integrated goal remains
active and incomplete; elapsed checkpoint time creates no capability claim.

Current implementation joins owned paired renewal, authenticated quarantine-only
restart recovery, a redacted account-bound model catalog, shared CLI/Qt
first-account enrollment and bounded native-producer refusal diagnostics. These
are Omux-owned integrations; no vendor-provided Omux hook is assumed.

The product remains install/activate, authorize sources once, verify usable
authority and maintain renewal, then use ordinary native applications with
preserved process/history and no accepted-work replay. The optional extension
acquires declared browser data through native messaging; it cannot by itself
supply application continuity.

## Version-bound results

- At `53628c3d`, all 460 original runtime cases passed after durable report
  ordering/duplicate acknowledgement and fixture corrections. The individual
  full-suite budget is 900 seconds inside the unchanged 1,200-second supervisor.
- At `9b0fcc29`, owned renewal compiled and 477/479 runtime cases passed.
  The remaining concurrency expectation and real startup SQL recovery refusal
  were diagnosed and repaired.
- At `947db8ff`, four focused renewal cases passed: same-generation independent
  work with an accepted-work generation-switch fence, stopped issued renewal,
  expired original deadline and unrelated account forget. The original
  authenticated epoch is preserved; recovery never reconstructs a refresh
  ticket or replays a spent refresh credential.
- At `c5ea4936`, eight selected targets passed: storage124, transport174,
  catalog parsing4, native diagnostic38, Qt transport/paths, formatting and
  documentation. Runtime and Qt enrollment/setup had compiler failures.
  These overlapping suites are not unique-case totals.
- At `c447be20`, CLI and Qt control binaries built, setup UI/format/docs passed,
  and the full runtime completed 485/493 with no skipped cases. Seven failures
  stopped in a shared fixture before production; one exposed a real parser
  allocation-failure identity defect. Qt enrollment stopped before handshake
  because the fixture did not establish the required private socket.

The original failed receipts remain immutable. No failed build, incomplete
target or empty XML row is counted as PASS.

## Corrections after the full runtime checkpoint

The catalog dispatcher now handles initial parsing failure at the original
invocation: null JSON-RPC identity, the existing refusal code and original
parser error. It cannot reparse with the reply allocator after actor allocation
failure. The existing allocation gate and assertion remain unchanged.

The shared catalog helper represents only its empty anonymous tuple as the
intended JSON object; other object guards and test assertions retain their
original behavior. The UI fixture uses the same checked private socket setup
as the passing transport fixture. Production peer and socket guards remain.

The current focused catalog target executes the existing actor cases.
No containment, deadline, allocator gate, assertion or test-skip policy changed.

At `baa33e88`, the focused catalog target completed12/13 cases successfully.
The remaining case concerns an in-flight pause and unrelated metadata revision.
The original queued-ingress allocation/identity case passed unchanged. Qt
enrollment advanced to its first cancellation assertion (Exit18); its follow-up
is still open. Format and documentation passed. The full493-case regression
has not passed at this successor and must not inherit the earlier460-case PASS.

## Execution, cleanup and next proof

One coordinator executes through the locked Nix/Bazel graph: 4 GiB memory,
512 tasks, CPU200%, swap0 and an overall1,200-second deadline. Routine checks
reuse the qualified per-checkout output base; other lanes retain separate
receipts and retire their disposable output/user roots after evidence capture.
Explicit R-C618 residual sweeps preserve receipt.json, supervisor.json,
test-evidence* and workload.log. Filesystem-wide space/inode snapshots are
distinct from removed-entry/last-link allocation counters.

The next product gates are installed first-account enrollment with the normal
OS vault, the exact maintained native candidate and ordinary accepted-history
resume, followed by real same-process handoff. The current native source model
PASS does not qualify its genuine Rust producer. Current retained usable-account
counts and normal-vault readiness remain Unknown; earlier one-account removed
fixture evidence retains its original scope.

Unmodified Codex, live handoff and Darwin activation remain unproved. Chromium
human permission proof, extension signing/persistent delivery and publication
remain separate gates. The Linux-only Home Manager guard is retained; Lab's
Darwin signing leg is welcome under the already-recorded requirements.

No live provider calls, production service activation, signing, publication or
merge occurred in this continuation. No achieved SLO or contractual SLA is
claimed. Reliability success and timely safe refusal retain separate scopes.

[PR541](https://github.com/Jesssullivan/oauth-mux/pull/541) remains draft.
[Renewal carrier](https://linear.app/tinyland/issue/TIN-3032),
[installation carrier](https://linear.app/tinyland/issue/TIN-2063) and
[Codex carrier](https://linear.app/tinyland/issue/TIN-5338) retain their completion
states. [Darwin requirements](https://github.com/Jesssullivan/oauth-mux/issues/542#issuecomment-6112773277)
are already answered; signing alone does not establish activation.

## Focused follow-up — CF-1507 at a2d3677b

At exact source `a2d3677b7b7422e7921067821234ffd70fc142d5`, CF-1507
(epoch `be532e4e-ed82-4452-b3e7-cd2e552bbbe6`) completed with outer/workload
exit 0/0. All four declared targets passed: the focused catalog actor's 13 cases,
Qt enrollment/cancellation/recovery fixtures, formatting and documentation.
This closes the focused follow-up at this source; the earlier 12/13 and Exit18
failures remain dated evidence. It does not establish a full 493-case PASS.

The retained raw receipt is SHA256
`ac57d4eec0831744b1018201eed7cb5f2f0bb12ce2f492c6725ea0ebbadfccf7`;
test-evidence manifest
`c2e57fd402d9c75685e23679620a1294ced881a70766573511a2b23829a3b7a6`;
workload log
`b671f5b7933375a8bf0e7532945de06ffa6d17b639599812158b2f4ec3d46ed7`.
Generic cleanup metadata reports empty/unproved with zero ownership readbacks;
cgroup absence alone supplies no owned-cleanup qualification.

The separate finished R-C618 residual sweep for this epoch removed 559,705
entries and 559,705 last-link inodes, with 1,031,372,800 observed allocated bytes.
Its named output-base/user-root removal preserved receipt.json,
supervisor.json, test-evidence* and workload.log. These per-entry counters are
distinct from filesystem-wide net changes under concurrent allocation.
The durable residual result is
`2026-10-12-R-C618-CF1507-residual-result.json`.

As of the retained 15:18:43 UTC readback, FULL-1518
(epoch `b70dd15d-0065-4d3f-a349-8d841cbf69c8`) was LIVE at the same exact
source/graph. Its whole 493-case regression result remains pending here.
No terminal outcome, count or cleanup result is inferred.

### Full runtime terminal follow-up — FULL-1518

At the same exact runtime source and graph, epoch b70dd15d-0065-4d3f-a349-8d841cbf69c8 completed with outer/workload exit 0/0. All 493 runtime cases passed; formatting and documentation also passed. This closes the combined runtime regression at this source. The earlier 485/493 failed receipt remains unchanged.

Raw receipt SHA256 `e361ccfa68a42bc0c1792aa2d9dde49c578fc2ce14ce1aee1ce48e1d0252d602`;
test-evidence manifest `041d11e642fc2cb734fa1598d1f00f3b411af45b42eb9752020c54f420528451`;
workload log `a9c01f656130f645981f576e099c0b8992a283c8d02b177cfd6924a31e8f45a3`.

The three-target ordinary-check invocation reused the qualified per-checkout output base. Its shared base remains working cache; copied per-epoch results retain their own source and target bindings. Runtime-model success does not qualify an installed daemon, normal-vault enrollment, provider acceptance or native continuity.


Focused fixture PASS does not prove installed first-account enrollment,
private-pipe/default-browser navigation, normal OS-vault readiness, current
usable-account counts, provider acceptance or genuine native producer output.
Ordinary native launch/resume, same-process handoff, unmodified Codex and
Darwin activation remain unproved. Signing and publication remain separate.
The original integrated goal is still active, overdue and incomplete; its
clock and existing resource/deadline limits are unchanged.


## Native producer prerequisites — 16:19 UTC continuation

The explicit catalog source/HUB family is implemented at `45748264`.
Its seven source predicates, four admission predicates, six prior source
predicates and twelve prior model-admission predicates passed. The complete
147-case guard suite passed at `73d5bb39` after deterministic positive-fixture
timestamps; production freshness and negative checks were unchanged.
GR-1559 raw receipt is
`3831aa977da6e83ef85489a1318325b16ecdc8a35aa04f74fb7f5500278222cd`.
Exact two-target successful source/HUB output retention has five filesystem
cases; bare, extra-target, missing-product and failed runs gain no new retention.

CS-1603 (`3cadbff9-6ab8-4b2f-a94b-bfc9e5980def`) did not qualify the genuine
producer. It ended outer125/workload1 with a normal nonzero workload and verified
owned cleanup, two readbacks and empty descendants. This is not a timeout or
Rust result. Its raw receipt is
`c817a3bf64e0b68f1c482d3609105556fb6fa777bbf52e599461a1899d8d9f59`.

The selected query registration and plan payloads were removed by this
coordinator's R-C618 cleanup; their original receipts/logs/XML remain. Those
downstream dependencies were missed in the hold list. The selected schedule
obligations are also absent; their removal origin is not asserted here.
The correction adds only three exact successful singleton output-retention
contracts for schedule, plan and reserved query registration, with six new
filesystem cases. It does not relax SDK, source, freshness, ownership, admission,
clock or resource comparisons.

The next ordered work is: check the changed guard; regenerate schedule and
generated siblings; publish a new selection from actual results; run plan and
registration on identical clean source/graph; select their new actual proofs;
then retry the source/HUB producer. Old paths, bytes and receipts are not
replayed as new inputs. New guard cases and genuine regeneration remain unrun at
this source update. Native20, ordinary accepted-history resume, live handoff,
retained normal-vault enrollment and Darwin activation remain unproved.

## Native prerequisite regeneration and cold driver checkpoint — 2026-10-12 17:43 UTC

The genuine regeneration sequence completed without replaying old payloads:

| Run | Source | Actual outcome |
| --- | --- | --- |
| SCH-1625, epoch71acc354 | fa979cef | Schedule qualification0/0; original obligations and generated siblings retained. |
| PLAN-1647, epoch3abf3f2a | 0cdc4b48 | Restored seed-plan qualification0/0; original262277-byte result retained. |
| REG-1708, epoch16ee0da9 | 0cdc4b48 | Reserved fixed-root query registration0/0; registration, store-paths and report retained. |

Plan and registration used the identical source and graph30a6e6f9. Both reserved original supervisors closed with verified ownership, two cleanup readbacks and empty descendants. Each run retired423 user-root entries. The schedule-derived selection and subsequent query selection use actual original output paths and copied log/XML identities. The plan explicitly leaves complete-build, SDK and native-runtime qualification false.

MODULE now selects seed configuration3be8efae/68948d69 and query configuration45a98e3c/30d1edcd. The old absent outputs were not recreated. PLAN-1647's immutable administrative pre-action incorrectly included two SOURCE-only clock descriptions; a durable correction records the actual unchanged seed-plan1200 envelope/private-work and cleanup contract. No execution argument, deadline, guard or proof predicate changed.

CS-1715 at05ee54f6, epochdcb383d3, progressed past missing query inputs and refused missing N1/3ace and N3/95f physical source bindings. It ended outer125/workload1 as a normal nonzero workload, with verified cleanup/two readbacks/empty descendants. Source7 passed; the producer was NOT BUILT and has no successful XML. Neither source/HUB nor SDK/native qualification followed. Original evidence was copied before the remaining disposable cache was independently pruned:279850 entries,565477376 observed last-link allocated bytes. Allocation counters are not a physical-space recovery measurement.

The reviewed cold driver V2 was adopted atbf2249e4, graph447702f5. NM-1728, epoch0187b38c, passed all nine declared targets:

| Predicate family | Actual methods |
| --- | --- |
| New catalog driver | 10 |
| New exact admission | 4 |
| Full execution guard, including new four retirement cases | 157 |
| File-writer source/model regressions | 38 |
| Previous native admission | 12 |
| SIWC source regressions | 6 |
| Catalog source regressions | 7 |
| Previous catalog admission | 4 |
| Documentation | PASS |

Counts overlap and are not unique native test totals. Runtime493 remains the earlier exact a2d3677b proof; production runtime files did not change in this slice. The driver keeps source:null. Its four complete normal native unit targets and35 required Rust methods remain UNRUN. No compiled native image, ordinary accepted-history resume, real handoff, retained normal-vault account count, unmodified Codex or Darwin support is established.

NM-1728's original supervisor closed0/0, recorded empty descendants, and its cgroup was absent. Its standard manager-cleanup row remained ownership-unproved/stop-not-requested; this is not a reserved manager-ownership proof. Test evidence was copied before an independent R-C618 owned-filesystem qualifier cleared306716 disposable entries,772272128 observed last-link allocated bytes, with no service signals. Native/source/SDK and freshly selected schedule/plan/registration inputs remain held.

A complete finite metadata audit found only N1/N3 missing among selected source/proof/control domains. C11/N5/N9/N10 declared members,188594 SDK nodes,540 JDK nodes,103 query roots and4248 generated roots were present with the stated metadata predicates. No byte/NAR or fresh SDK/custody qualification is inferred from that audit.

The implementation direction is a distinct selected-N10 content-source intake: independently authenticate the full existing source inventory and genuine producer evidence, freshly prove every current source byte/link/alias/full-nine witness, apply the current exact V4/catalog changes and regenerate the full HUB with unchanged original SDK/JDK/query owners. Historical SourceProofSession stays unchanged and is not falsely claimed to have rerun its missing ancestors. Direct retained input is a tactical repair. Portable completion additionally needs digest-addressed declared source/provenance transport and complete SDK/tool transfer with clean second-environment proof. Implementation and new genuine source qualification remain pending.

Durable exact receipts and review joins are under /home/jess/.local/state/omux-proposals-20261010/root/docs/agent-notes:

- PLAN-1647 rawreceipt f0c8f284988e319ca954b672df2ea2f767659d726ccfcac9b69152ef74130b04; manifest455099f9f2247533421321dabcfa427e30f6f532762cc148a51f023f2286c558.
- REG-1708 rawreceipt9b6eb41017962f3d7e7993e3cf7d7eb74e42453f31fd19a41ec10f37434127e8; manifestfeff135e4246c92c28eac1485c6cf317a00b5c789dcc0b085c8c2f32b17f8bc9.
- CS-1715 rawreceipt1c279b13a239980e5feae312839157ab945c2435900b2fa9500c86c312e03653; manifest9e53e4d3341b9046c5c87ce70d30254d4d0c8bac033f9d7f2a4417cf279dc29f.
- NM-1728 rawreceipt0dc0de71aec89cd979c991b6c6d7b68d484546b541daadae6f34e41d0e217a5c; manifestdeba696d924dfa52e07bfe4963d5a917da78a1de992d9a0ea634aeedd52dcda5.
- Actual query-selection publication receipt1fe37f2b41a707d5321da9ed6021bfbe6061b9fc83ecad30dc46fcbe543c83d4.
- V2 full source review7b4a855962fdf86c272cefd75a7551b5b2abc45b80e64b4f9346f29b3bd09da4; current composition reviewcca470c9a1b74f0d9b49942a960ce16f64b13280879f29f68533b8b9171335c9.
- Complete dependency assessment98ef634a8748ff4e4d7f32106c5ba80b2da263dc4f999cb50ca28651750e98f7.
- Root implementation direction760e23127a362abef3c7c498a7c34345251e4bca5a05994b144f9f69b49eae9c.
- Factual Linear readback42f48e405056422e5f0c3b2b75be00e1fa91a0426245c23d7c3ce7540a6d128d; subsequent source/model reconciliation still requires its own readback.

The original15-hour integrated objective remains active, overdue and incomplete. No clock reset, release/support promotion, achieved SLO, contractual SLA, publication, signing or merge follows this checkpoint.

## Selected-N10 content intake — 2026-10-12 19:18 UTC continuation

The reviewed 22-path native content intake/SOURCE-HUB implementation was adopted
at `26d5b0ac44a3f738804fd0080fb147d49b51473c`, graph
`5a2882c6b214bc460bd170341d90ec4a14fde1b214172e9e4f270603efa803d5`
(518 files), after two complete source reviews. Adoption did not qualify the
genuine producer, SDK or native runtime.

CM-1903, epoch `0eff8b61-ab09-446b-af7d-0203bbdc64ac`, completed with
outer/workload exit 3/3: 11 of 13 declared targets passed. Both the 15-method
intake suite and the 28-method content-source suite stopped at the same imported
fixture assertion in `codex_native_n10_source_intake_test.py:291`. It attempted
the replacement refusal before establishing the first pinned capture. The
original failure remains evidence; these are overlapping populations.

The reviewed one-file fixture correction was adopted at
`dac438c796898d5f9c4d1a5f3a171873d71b80c6`, graph
`7c7b9e94a1f3a79cfddb8a05227990a49113b0e44c74d066376fdab95c3d04b3`
(518 files). It establishes that initial capture before the late same-byte
replacement; production predicates are unchanged. CF-1914, epoch
`f26bc7cd-cb1d-4a41-9e30-76bb7040cba3`, completed outer/workload exit 0/0:
the intake 15 and content-source 28 methods passed. Do not sum them as unique
tests or replace CM-1903's failed outcome. The earlier full 493-case runtime
PASS remains bound to `a2d3677b`; no newer full-runtime result follows here.

| Retained run | Raw receipt SHA256 | Test-evidence manifest SHA256 |
| --- | --- | --- |
| CM-1903 | `b34466d63c60c5c1eabf504fc7190cd100b2f1f1be2e261bedfd5b7e791fd56d` | `19e413c0689cc90137cb6953e047b73ea14c56ab19328d363c06ec8ecd84634b` |
| CF-1914 | `3c5ff13448b88bcd139ac5d240e9eafc3bbc471cbe60e3aadd86f5a59e02aa2a` | `e40d29d416f04a61561061e59a63048decfdedd6efa74172d93749d0b0b298bc` |

CM workload log SHA256 is
`236254f0d6faf7ff5db42c4303b01290486dc01acfde6e3a7eaa90cdc6a726e5`;
CF log is
`d24203b3722486c73c56580bd1260b162e1c207621cdb753aa534432acb5f065`.
Both standard cleanup rows report ownership-unproved, zero readbacks and
stop-not-requested despite empty descendants and absent cgroups. Neither
qualifies manager-owned cleanup.

Separate administrative R-C618 sweeps removed 361,373 entries for CM
(799,293,440 observed last-link allocated bytes) and 159,624 for CF
(698,351,616 bytes). CF's automatic retirement was separately partial at
37,122 entries. These attempt counters are not combined or treated as
filesystem-wide recovered-space measurements. The keep-list preserves
`receipt.json`, `supervisor.json`, `test-evidence*` and `workload.log`, with
copied evidence.

As of the retained 19:18:49 UTC observation, CNS-1918, original handle 38103,
epoch `4323f91c-c4a2-4465-8400-06dc9a5db8cb`, was LIVE at `dac438c7` and
the same graph. It runs the exact reserved content-source test/producer pair.
Its genuine SOURCE/HUB and complete SDK/NAR/source qualification remain pending;
no terminal PASS, native output or artifact is inferred.

### CNS-1918 terminal — original attempt preserved

The original CNS-1918 supervisor completed outer/workload exit 125/3.
Its content-source 28 methods passed, while the genuine producer failed in
5.9 seconds with only the generic “native SIWC catalog content source refused”
diagnostic. Bazel reported 332.791 seconds overall. This is a normal nonzero
workload outcome, not a deadline or successful producer output. The first
failing locus remains Unknown; model PASS does not locate it.

Raw receipt SHA256
`50a5a45c4327e4a92dc372907091cf2ee43e81fce41ecd67d4f2f61862d4ffa9`;
test-evidence manifest
`0dc5db68f6f3097ab1386762437011e518952787f1925ee2e5a1af0ec07f2db7`;
workload log
`7e6c6ba3156dafc27253b83ade71787a697e5e20bb4f8b9753e708966285dbf6`.
Reserved cleanup verified owned terminal custody with two readbacks and a
successful stop; descendants were empty, the original cgroup was absent and
no controller error was recorded. This qualified refusal/cleanup does not
qualify SOURCE/HUB, SDK/NAR content or native continuity.

The separate administrative prune, original handle 18280, completed exit0.
It removed 668,680 entries/last-link inodes with 742,457,344 observed allocated
bytes. Its journal is
`ee2dbad526cbf6631eed03c0099667af1a68046da09df0d12229ef2a466b3c02`.
The keep-list and copied evidence remain preserved; these allocation counters
are separate from filesystem-wide net space changes and manager cleanup.

The full SDK catalogue at this checkpoint is structural evidence only:
no byte/NAR/SOURCE/HUB/native qualification follows. A deterministic carrier
proof mode600 capture defect would refuse if that path was reached; this has
not been established as the actual CNS-1918 first failure. A minimal typed
role repair and bounded diagnostic review remain pending. No retry PASS or
new selector output is predicted.

The native selector remains `source:null`. Native 35 methods, ordinary
accepted-history resume, installed first-account/normal-vault custody, current
retained usable-account count, provider acceptance and same-process live
handoff remain unproved. Stock Codex, Darwin activation, signing and publication
remain separate gates. The original goal is active, overdue and incomplete;
its clock, resource bounds and qualification requirements are unchanged.

## Current site prerequisite source — 2026-10-12 19:39 UTC

The reviewed eleven-path site selector/retention transaction was adopted
serially at `6688edc86d5025994d2a742b5d3e1bb89d9ccaea`, graph
`d7e2e0bc8fd8efdb00970716f26e6d1d92a82163eea93a040ebba0892833a335`
(521 files). It implements explicit fresh candidate/version input selection
and four exact singleton original-output retention contracts. It restores no
old cache and adds no inherited genuine site or native qualification.

As of the retained 19:39:02 UTC readback, SM-1940, original handle 75115,
epoch `aa8f4f37-7025-49b7-941e-91ba14d1bc80`, was LIVE at this source.
Its six declared model/docs targets were pending in that observation.

### SM-1940 terminal — five targets passed, guard fixture error retained

Original handle 75115 subsequently closed outer/workload exit 3/3. All six
targets built; five passed: selection5, version-qualification5, closure10,
site-guard23 and documentation. The guard suite completed 166/167 successfully,
with one error in the positive UUID inventory fixture at test line1287.
Production `selected_site_inventory` called `private` at line825; the
sandbox ancestor was rejected at line730. This is a test-ancestry seam missed
by source review, not a reason to weaken production trust. Minimal fixture
correction and its actual retry remain pending.

Raw receipt SHA256
`ecc4cbd81c363b5d3840621c18b52fdb65e527f56ed55566e33b15c508d6719c`;
test-evidence manifest
`67e6f6974c75a6badfbf3d6794a4c600af28c2ef09106edbcfed8a53b91322b0`;
workload log
`94a8d7f04e925e15c8ea178c5194a7300dc0cf132feb7c78172a81d9fe2d683b`.
Standard cleanup remained ownership-unproved/zero readbacks/stop-not-requested
despite empty descendants and an absent cgroup. Automatic retirement was
separately partial at 21,127 entries. The subsequent closed administrative
handle92191 removed 244,067 entries with 739,975,168 observed last-link
allocated bytes, journal
`02474178232b55954d671ce73f2877139c11eeb34e84b02e72c6f8278afe618e`.
These counters are distinct from manager cleanup and filesystem-wide net space.

Root's early evidence capture preceded original-handle closure. Durable
`2026-10-12-SM1940-early-capture-order-correction.json` restored the original
executor association; `2026-10-12-SM1940-original-handle-terminal-readback.json`
later confirmed its actual terminal exit. Copied artifacts remain unchanged,
and no next project execution was admitted before closure. This ordering
correction does not convert the failed guard into PASS.

Genuine site prerequisite production, current artifact import,
build/publication and all native/installed/provider gates remain separate.

Lab [TIN-2063](https://linear.app/tinyland/issue/TIN-2063) comment
`a9559d76`, under R-C642/R-C643, reports cleanup of 113 home bases,
approximately 47.15 million inodes and 73.5 GB. These are Lab-reported totals,
not Omux-attributed removal or measurements. The b9/d20 entries remain
Unknown/held. Current Omux execution/output roots are already fast-local;
home coordination, control and source-only receipts are not execution trees
to delete. No additional cleanup action follows this checkpoint.

The original goal/acceptance clock, native `source:null` selector and wider
custody, ordinary-resume, native 35, live, stock, Darwin, signing, publication
and reliability gates remain unchanged and unproved.

## Reviewed repairs and RM-1951 — 2026-10-12 19:56 UTC

The bounded site fixture correction was adopted at `9f5b8721`; the reviewed
five-file typed carrier-proof role/diagnostic correction followed at `8c69a9a4`.
The current source is `8c69a9a4440a95261d18f2b3e4e59f1a5a8f83dd`, graph
`f9d029fcb5e3ddcd5debab9127514efcf96c2e18e7fff1629a9dafbc38ce631f`
(521 files). The earlier CNS-1918 first failure locus remains Unknown.

RM-1951, original handle 24017, epoch
`067f449f-bd4b-435d-ab89-b6b5adafa36c`, closed outer/workload exit 0/0.
All six declared targets passed: intake 19, content-source 36, file-writer 38,
SIWC-source 6, guard 167 and documentation. Intake/content populations overlap;
these are model predicates, not a unique native test total or genuine
SOURCE/HUB, SDK/NAR, compiler/runtime or continuity qualification.

Raw receipt SHA256
`7d9d5e6634292c07541ddd3e0ac7d351659d0b8e25c048ac10dda04bb4f9c34d`;
test-evidence manifest
`50fb46956ac5ec938bad58e1af175b7f22d5a5ad87008840be039e36b5862250`;
workload log
`12268bd06716f30a0f24e32777e05e5f37c66144fb89b7103830443551a1989e`.
Standard cleanup remains ownership-unproved/zero readbacks/stop-not-requested,
despite empty descendants and an absent cgroup. Automatic retirement was
separately partial at 25,025 entries. Closed administrative handle 74546
removed 240,843 entries/last-link inodes with 738,996,224 observed allocated bytes,
journal `e1d2e95ecf9e3ddd35ea7573015eddb3ec5b6c65e2abbcbfb8a00ad192dbc2ce`.
Keep-list/copied evidence remains; allocation and automatic/admin counters
are distinct from manager cleanup and filesystem-wide net space.

As of the retained 19:55:58 UTC observation, CNS-1955, original handle 63424,
epoch `8955d8e3-28b5-4783-b4a6-2fc65a5fcdd4`, was LIVE at the same 8c/f9
source/graph. It is the new exact reserved content-source test/producer pair.
The original source 600/action 840/outer 1200-second caps are unchanged.
No terminal result, emitted SOURCE/HUB, byte/NAR or native qualification is
inferred from this LIVE observation or RM-1951's model PASS.

<!-- ROOT CNS-1955 TERMINAL INSERTION: after original executor terminal, append exact source/epoch/graph, actual exits/tests/output scope, raw receipt/evidence/log pins, cleanup qualification and original physical retention. Preserve the preceding dated LIVE observation; no inferred first failure locus or future PASS. -->

Native selector `source:null`, candidate ordinary/live proof, normal-vault
retained usable accounts, unmodified Codex and Darwin activation remain
unproved. Signing/publication/SLO gates and the original active, overdue,
incomplete goal/acceptance clock remain unchanged.

## CNS-1955 actual terminal — 2026-10-12 20:09 UTC

Original handle 63424 closed outer/workload exit 125/3 on the same
`8c69a9a4440a95261d18f2b3e4e59f1a5a8f83dd` source,
`f9d029fcb5e3ddcd5debab9127514efcf96c2e18e7fff1629a9dafbc38ce631f`
graph/521 files. Content-source 36 methods passed; the genuine producer FAILED
in 293.5 seconds, with Bazel 595.153 seconds overall.

The bounded redacted diagnostic reports class ValueError, errno 0 and
`sdk-carrier:713,646,656; sdk-inputs:195,167,103; sdk-carrier:88,47`,
truncated 1. The terminal locus joins the fresh NAR stream's alias/current-parent
custody checks to `Clock.tick` at carrier line 88, which requires
`time.monotonic() < self.deadline`. `HeldOriginalSDK` lines 263–273 bind
the SDK/SOURCE cutoff to original entry + 600×10^9 nanoseconds. Thus this
attempt reached the original 600-second SDK/SOURCE deadline during those
fresh checks; it was not the 840-second Bazel action timeout. The truncated
trace supplies this bounded diagnosis, not complete downstream qualification.
CNS-1918's earlier generic first locus remains Unknown.

Raw receipt SHA256
`59c98d855d665cbc00562eea75b1c1829a073ca99d47be6c5aac22fa667830ab`;
test-evidence manifest
`d109280375e1934f919ea33dc13d12c6fa5e81fb29d1194c0b1c03446532d0d1`;
workload log
`394b8cb2feaa957e7163b7c6ee1591b6b617e67a71d7a80c4390fdc61d0555bb`.
Owned reserved cleanup verified two readbacks and successful stop, with empty
descendants/absent cgroup and no controller error. Automatic retirement was
deferred at 0 removed entries; these are separate outcomes.

The subsequent administrative handle 31069 closed exit 0 and removed 668,680
entries/last-link inodes with 742,453,248 observed allocated bytes, journal
`4c57b075cd6a0853f9656aa92930733a0f1f8c453d0016b72e895c10a7b10527`.
The keep-list was reverified; copied evidence remains, with no source change
or service signal. Removal counters and filesystem-wide net changes retain
separate scopes.

Next work is two focused private implementation lanes: native NAR stream and
custody costs, and HM declared-catalogue overhead. Reviews and actual changed
source gates must precede another attempt; original source 600/action 840/outer 1200
limits remain unchanged. No SDK/NAR/SOURCE/HUB/native qualification, native 35
execution, ordinary/live/provider proof or Darwin activation follows this
failure. Native selector `source:null`, normal-vault retained-account gates and
the original active, overdue, incomplete goal/acceptance clock remain unchanged.
