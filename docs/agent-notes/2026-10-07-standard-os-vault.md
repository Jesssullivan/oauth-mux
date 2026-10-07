---
title: Standard Secret Service setup and actual native build limit
date: 2026-10-07
status: active
summary: Installed Locked control and controller/runtime models passed; restoration encounters refused session IPC and vault binding remains operator-owned.
refs:
  - TIN-2063
  - TIN-5338
  - TIN-1818
  - https://github.com/Jesssullivan/oauth-mux/pull/535
  - https://github.com/Jesssullivan/oauth-mux/pull/536
  - https://github.com/Jesssullivan/oauth-mux/pull/537
  - https://github.com/Jesssullivan/oauth-mux/pull/538
---

Authority: user-authorized normal OS unlock via Lab SOPs and the explicit
instruction to check Neo; repository AGENTS.md; R-N11/R-N12/R-N13.
The original five-hour checkpoint was missed and the full objective is incomplete.

## Source composition and OS boundary

The separate standard-vault branch starts at signed resident I10
`15facb976ae43ce1729e56de817f864064869351`. Root applied reviewed metadata
proposal SHA256 `c057135d02ba54970f73cc42a74c6c29e144f9013c267d79ea701668e64f0b1d`
and standard carrier proposal SHA256
`9e15d5f7b0c9d06d8843fbc45cfa672fc086cb5e520727442f5a78a2f95ba218`.
Independent review of the actual composition found no static blocker or drift.

Version two authenticates the actual local bus peer and the existing unique
service owners by UID, PID and stable process start. It performs no executable
inspection as service-role authority. Version one's executable/factor contract
remains unchanged. The standard namespace contains only the existing user bus;
it does not expose SOPS material or a proprietary keyring control socket.

The new metadata action reads the existing default alias and Locked property.
Unlock uses the pinned unique service owner and standard Unlock/Prompt protocol.
The opaque collection path travels through a bounded private pipe rather than
argv or public output. Prompt completion is bound to sender/object/result, with
120-second prompt and original aggregate deadlines; cancellation remains explicit.
Neither action starts a provider, reads collection items or secrets, creates a
collection, writes a wrapping key, activates Omux, or invokes an account provider.

Helper-connection unlock is distinct from resident custody. Independent Locked
readback may remain true; actual resident readiness must be checked separately.
The standard path requires no assumed mapping from sudo to keyring credentials.

Required new tests: `//delivery:resident_standard_vault_models` and
`//tools:guard_resident_standard_vault_test`, alongside the existing vault,
enrollment and execution regression targets. These tests and actual new metadata,
Unlock/Prompt and resident custody readback are unrun at this source checkpoint.
Earlier I10 tests cannot qualify this changed graph.

## Neo SOP readback

Read-only public Lab inspection on Neo identified source HEAD
`ec51ffe238eb8919ec82b2a9d31507d7ac999df3`. Its current AGENTS.md assigns
the host-local `become/password` leaf to sudo (R-C277/R-C288), not to a
Secret Service collection. Searches of public Nix/host/Home Manager/role/script
configuration and operation/agent notes found no declared keyring-unlock
factor binding. This is inspected source scope, not proof of every host's
private configuration or current collection state. Linux MCP OAuth storage
being configured as file-based supplies no OS-vault password mapping.

The first SSH reads refused before authentication because the installed
system crypto policy named algorithms unsupported by the pinned SSH client.
Root used the existing source-inspection `ssh_policy.operator_config` helper:
bounded read-only public configuration copy, supported subset of the original
permitted algorithms, existing owned GPG agent socket, strict existing host-key
verification, batch mode and a thirty-second timeout. Successful source reads
made no Neo edits, builds, service changes, key listing or secret reads.
Authority/alternative receipt: root | explicit Neo public-source inspection |
user instruction check on Neo | R-N12/R-N13 | pre-auth crypto-policy refusal |
compatible read-only client configuration and successful public-source readback.

I10 declared run `c4a92d60-dd85-4890-a5ee-a145d7b44525` ended with exits 3/3,
empty descendants and preserved evidence. Receipt SHA256
`76da81cd50345dc227808756144951fcd4a6b6e9d260c88c8af1e1c2a1364093`.
Vault models, fresh-runtime consumer, enrollment guard and source receipt passed.
Only docs_check failed on its unclassified I10 checkpoint note. This branch
classifies both checkpoint notes before its own declared verification.

## Actual native outcome

Frozen N4 `b332f596c711e45a7fea4ebcdae559f543cc3816` qualification/CLI attempt
six, aggregate eight, ended in epoch `5a973300-9c1b-49b1-99ff-8460317eaeba`.
Receipt SHA256 `12543b3f84d6db2fd4c70074248da87627f5666df14c783f281ab7bc5f2013c0`:
guard exit 125, workload exit 9, `preservation-failed`, descendants empty,
controller failure null. Source/export after-cleanup verification is false and
phase-two transition after-cleanup verification is null.

Independent exact-unit readback showed `Result=oom-kill`, MemoryPeak 4294967296,
MainPID zero, empty ControlGroup and failed/inactive workload. The frozen 4 GiB
bound held; no broader host or process-tree observation is implied. The guard's
cleanup ownership remains unproved, rather than being upgraded by this note.
Schema attempt seven, fresh packaging and native/live proof remain held. No retry,
counter reset, cap change or source/cache mutation is authorized by this receipt.

Zero accounts are durably retained. Actual owned inactive package replacement
remains the existing installed proof. Ordinary native resume, accepted live
history, two-account same-process handoff, browser consent, Darwin, unmodified
Codex support and achieved reliability targets remain unproved.

## Actual standard-path outcomes and owned first-start source

Exact signed standard source `a948203789b9bff1d5726591bcf86dc4ce161916`
passed all eight declared new/regression checks in
`e4f651ce-b033-4433-92f5-b1243018ae5e`; receipt SHA256
`aebbe300e26471563f858a2a999739874e9d09a81af09566a4a89caf0c1caa33`.
Exits zero, descendants empty, controller failure null and evidence preserved.
These checks include the compiled prompt models and docs classification.

Actual standard metadata `02de29b9-2e6e-4532-8299-cc4155d880b6` passed;
receipt SHA256 `836955af4583a7b46a11cc705725975f18537a333c7270b125ac23170838a281`.
Stable bus/service identities and existing default collection were observed;
Locked was true. Collection path stayed in private metadata. No item/secret,
factor, provider, daemon or enrollment action was performed.

Authorized standard Unlock/Prompt `8f2bc14d-3ebb-40cb-8175-1491955a0f42`
refused with `unlock / cancelled`; exits125/125, empty descendants,
controller failure null. Receipt SHA256
`e384a1c9c4a50baefde7e7dd55f4dc7b64cc6d3d0c3be9de59fe255ed607f7c5`.
Cancellation does not identify human interaction or show that a prompt was
visible. Post-helper Locked state and resident usable custody remain unproved.
No retry or factor read followed. The user was asked for normal OS unlock or
the Neo operator's nonsecret declared factor binding; no password was requested.

Root now applied independently reviewed owned-first-start proposal SHA256
`24a2e5294ec125fae1d8742b25675dc38e6654f54774abb3e29339191121fa2a`
to the existing carrier/profile. It permits only the actual qualified installed
archive and owned enabled inactive unit with its sole private zero-byte lock.
It holds lock metadata without flock, starts only that unit, and reports control
readiness separately from usable custody. Preexisting database/unknown state,
modified payload/unit/alias, active process, stale qualification and wrong socket
mode/peer refuse. Normal post-start authority lock is admitted by metadata only.
No enable/reload/reinstall/source/provider/factor/vault-helper action is added.
The ten new models and actual first start are unrun at this source checkpoint;
the earlier eight-target result cannot qualify this changed graph.

## First-start outcome and source-record correction — 19:35 UTC

The seven declared checks completed in `635b6aea-b1c2-4fa7-b945-2e31afd8fe41`
with exits zero, empty descendants and preserved evidence. Receipt SHA256
`6a640a3c7b2619a170230f0db5c9f442e0cec32a1c0cda0008ea6dd87408dbfb`.
Root omitted the reviewed Add File `delivery/resident_owned_start.py` from the
signed `14a6664d01f4131cfd1f7f08c01d05897fba9756` commit. The file was present
throughout those checks and the actual start action; its exact SHA256 is
`a06854cc0daf166bd31b6fae6745b7aea29f62397e94970f49757df1c5e9dba6`.
Independent source readback matched the reviewed `24a2e529` patch payload.
The declared Bazel action inputs included this file; the controller graph digest
does not itself hash delivery Python bodies. Those receipts' recorded
`source_dirty=false` does not describe a fully committed source tree. No clean
signed-source qualification is inherited. This amendment includes the file.

Actual action `74ca7bab-abb9-4aeb-a14e-0a636024e5d4` built the archive successfully,
then ended exits1/1 with empty workload descendants and no controller failure.
Receipt SHA256 `e40a5c7fe972aad00169401bff6dafdb6367b8ecf650e91dd6bace2e757f9b65`.
Its resident readback verified an owned active bounded first start after cleanup;
control-plane health and custody require controller success and did not pass.
Exact user-manager metadata independently shows the installed unit active under
256 MiB, zero swap, 32 tasks and ten percent CPU. No stop/restart followed.
The resident is outside the completed workload cgroup and is intentionally retained.

Source review found a concrete fixture defect: `start_health` required protocol1,
while current `src/control.zig` and both engine health variants emit protocol2.
Root applies reviewed correction `27f4334e15c0e49f27f898e72060aaf33a5d36e5676e1b2d86eb11d0d681eec8`,
including runtime-shaped Ready/Locked cases and invalid-version refusals.
This does not attribute every possible predicate in the generic activation refusal.
Corrected checks and actual health inspection remain unrun at this amendment.
The Neo operator will identify the unlock binding; no factor value was requested
or read. Usable custody and durable enrollment remain unproved.

## Narrow installed lifecycle carrier

Root applied independently reviewed proposal SHA256
`2ac853f7b4091534d4bcb144bc7e1cbc72a6c4fa81b5f2f7b5b71ee3974e3447`.
`//delivery:resident_owned_lifecycle` consumes the existing qualified installed
archive and controller/tool inputs. It does not depend on the archive producer,
runtime compiler, native UI build or OS-vault probe. The existing first-start
carrier keeps its original role.

The new carrier admits only `observe-existing` or explicit `stop-idle-owned`.
Observation performs no service mutation. Stop requires the exact owned active
process/cgroup/socket and unchanged installed files, protocol2 Locked health,
disabled native admission and pristine zero-lock/no-database custody. It does
not stop a Ready actor, enumerate accounts or fabricate account counts.
It stops only the named owned unit, then requires inactive unit, empty owned
cgroup/control directory, exited original process and preserved custody/software.
Finite phase diagnostics contain no manager output, paths or exception text.

The actual action is queued under the existing complementary reservation and
original deadline. Static review qualifies this narrow low-impact owned stop
within user authorization; it does not replace required tests. Six new
lifecycle models, protocol regressions and actual stopped disposition are unrun
at this source checkpoint. After successful idle stop, root must run the
changed standard and native suites before any new native admission.

## Installed lifecycle proof and regression result — 20:01 UTC

On signed `6ae80bf67a3f73427ff47527baed9912b5d46f8f`, actual lifecycle
`1b79e0df-d5cb-4d38-8f4a-42f88759d83e` passed zero exits, empty workload cleanup
and independent after-cleanup verification. Receipt SHA256
`d91c388dbf4d63c4400bd372e7c878a34f6eea4b1e6b94dcffae01dd99870d4c`.
It verified actual Locked protocol2 health/handshake, unloaded custody, disabled
native admission and the exact owned software/process/socket/unit/cgroup, then
performed the explicit idle stop. Original process exited, owned cgroup/control
became empty, and installed software/pristine zero-lock state were preserved.
This establishes installed locked control and owned shutdown; account counts,
usable custody, enrollment and continuity remain unproved. No provider or factor
operation occurred. The resident build reservation is released.

All nine changed/regression targets passed in
`7b76fca2-aa30-4826-8a01-fa5393d6fc59` with empty cleanup and preserved evidence.
Receipt SHA256 `c42a223376ba51deb7ee2685304c56beda3c520b37ddb336d4be18d017a7efb9`;
evidence SHA256 `2eaedd203827eb81cb005e4d36cbedc1038c990fee013684689f3610532e1d8e`.
This includes lifecycle sequencing, strict protocol and closed-role refusals,
standard-vault models, enrollment/controller regressions, docs and source receipt.

Root reviewed and applied lightweight first-start delegation proposal SHA256
`a2f75059bb98f46d3a73bf43b7fa5aa9dbccd07f4f27c0c054ac71e307cd38b5`.
The small lifecycle carrier may now use the existing `start-existing` contract
and helper with the same explicit activation permission, qualified archive,
inactive/pristine admission, bounded process and strict protocol2 health.
The old carrier remains valid. Observation and Locked idle-stop policy do not
change. This permits later restoration without rebuilding runtime/UI artifacts.
The new delegation and changed action-join checks are queued; actual restoration
is unrun. Earlier nine-target evidence remains bound to `6ae80bf`, not this delta.

## Lightweight restoration models and verified enrollment metadata

Six restoration/controller/source checks passed on7b1d5b12ed52733396c0baf55dd80808064559ce in83395652-c171-4e99-8609-1a8b92a56c30, exits0/0, empty cleanup, controller null, evidence preserved. Receipt SHA0263f75025c5e8455354be13396b1decae4282c6cf5a5fa87c66012d17763069; evidence415a0b8b4aa1feb9d500f318ca4fcc0d0369d69d8824ff8c64483e37626d7d28. Actual restoration is queued after frozen native6b/global9 releases full4GiB capacity.

Source review found old enrollment acceptance identity={provider:codex} refused actual runtime provider+verified metadata. Root applied independently reviewed narrow proposal9124cd37138f0e413cb6ca8f1928537084c9e41c190c58455331d4cae471bd06: require exactly provider/verified and literal verifiedTrue; false, missing, integer1, stringtrue and wrong provider are refused. Existing source/account, active lifecycle, external ready access authority, expiry and generation checks remain. Shared Engine.publicAccountView emits this verified boolean across Setup23/I10/standard7b1. No runtime/archive/provider/credential/service changes. New enrollment contract tests are queued, not passing; prior checks retain their exact sources. Neo operator is identifying the OS vault binding; durable enrollment and live handoff remain unproved.

## Qualified existing-enrollment carrier — source delta

Root applied independently reviewed1605cea0451a3e53e8d73027e982bf24fbfa98a78dfbd31223095055f5621830. New //delivery:resident_codex_existing_enrollment consumes the same separately pinned installed I8 archive and successful clean BUILD qualification through exact existing_archive metadata, and declares no daemon/UI/archive producer. It requires owned/default enroll-existing, source permission true and activation false; optional explicitly authorized restart retains its original semantics. Heavy enrollment and lifecycle labels remain valid and reject mixed selection.

A held public software witness verifies the complete qualified archive/manifest, archive-derived installed payload/record/unit/config alias before and after, with no private DB/daemon.lock fence. Guard holds and rechecks that witness and binds public qualification/archive leaves and product directories read-only. The small wrapper delegates the unchanged enrollment controller after stripping only existing_archive, preserving provider verification, source O_PATH metadata, strict verified identity, usable external access authority, custody and retained restart checks. It adds no factor, credential reader, key operation, general Ready stop or runtime change.

Five meaningful new contract methods cover closed role/permission/qualification joins, exact successful delegation, provider and changed-software failure closure, a pinned TEST-vs-BUILD refusal before installed/private IO, and recursive/writable bind refusal. They and regressions are queued until frozen native6b/global9 releases capacity. Actual restoration, usable custody, enrollment and live handoff remain unproved.

## Current source authorization in enrollment acceptance

Root applied independently reviewed controller-onlye3914a73ea01ae94bffdec4e2b6d9c2430974cc3bab2146a2f7dc31311bfc5ce. Acceptance now rejoins the exact selected seven-field public Source and checks its Codex/native_store lineage, connected-or-detached status, signed-i64 authorization times and exclusive expiry against the same captured now. Missing/duplicate/extra source shape, bool/float/overflow times, future authorization, disconnection and expiry-at-now refuse before successful enrollment output. A different connected source cannot authorize this grant. Valid detached non-browser authority remains eligible, matching domain routing; grant generation and all strict identity/external ready access/expiry/account/source joins remain intact. Three meaningful methods extend the existing enrollment contract.

This changes only the controller and can use the unchanged qualified I8 software after model proof. Separately reviewed runtime projection proposal935a3c55ba04ca54e4ffa561233bbb00d18dcee039c592b906047b4cb86144f5 remains unapplied: setup's Usable authority phase can omit source-expiry status even though routing correctly refuses and complete readiness staysfalse. That runtime correction requires its own source/test/artifact/install qualification and inherits no I8 proof. Neither new controller methods nor runtime delta have execution evidence yet.

## Enrollment checks and readiness-source correction — 21:38 UTC

All eight changed enrollment/lifecycle/controller/docs/source tests passed on
signed e4d8bb636364afdda14b77fb84a8e265df2c93ea in epoch
87e4be20-dff3-49ba-91bb-dc9e09faf160. Exits0/0, descendants empty,
controller failure null, evidence preserved. Receipt SHA256
6f840f53a37e8e9d2bbbfbf55b48714ff149eaeadde9fc187f43db4332ef0340;
evidence SHA256 bb9d245bacb79aa3654ea111cd1f94919fd13a915e4e9a674c6e746ba679a110.
These replace the earlier queued status for the three controller deltas.

The first lightweight restoration was refused before an epoch, workload or
service launch: stage=operatorinputs, exception=OSError. No root cause is
established. Qualified public software/receipt/archive and private input paths
exist, the exact 32hex control directory is empty, and app.slice exists with
the owned unit cgroup absent. A narrowly redacted diagnostic is being reviewed.
The daemon has not been restored. OS unlock binding remains with the Neo operator.

Root now applied independently reviewed runtime projection proposal SHA256
935a3c55ba04ca54e4ffa561233bbb00d18dcee039c592b906047b4cb86144f5.
Setup captures one clock and requires the grant's exact source lineage to have
current authorization before displaying usable authority. Valid detached
non-browser grants remain eligible. The regression compares the displayed
phase with actual routing for current, detached, expired, future and disconnected
source authority, including an unrelated connected source and unchanged generation.
This supersedes the previous unapplied status. Runtime/source checks are queued;
installed I8 software is unchanged and inherits no successor behavior or proof.

Git receipt: root | own standard fork, exact engine/note paths | preserve actual
source correction and evidence | R-N12/R-N13 | Original index untouched |
invocation-local hooksPath=/dev/null, signed commit; declared Bazel checks remain
required. No credentials, factor, native auth/history or provider operation.

## Runtime source-authority proof and admission diagnostics — 21:47 UTC

{"cleanup": {"ownership": "unproved", "readback_attempts": 0, "state": "empty", "stop": "not-requested"}, "controller_failure": null, "descendants_empty": true, "evidence_sha256": "b1694deab7e3a04147cc62b6da58121aae436f69b6545c97b340a9b1f934b529", "evidence_state": "preserved", "exit": 0, "graph_sha256": "e8979cefcfb9a590507c37ef51c3b334061734250594125292986b1bd02caa4c", "id": "4b9d0642-2828-4d4e-ba1d-83dd44739fc9", "receipt_sha256": "7852008bc42edd5b0f1576fd5e806a3acbdc388f6d184b376975b6ea3a15fe26", "source_commit": "9e34f06394b32a38a0039c809cd09d653cdb737c", "source_dirty": "false", "target_results": ["//:docs_check                                                            PASSED in 0.7s", "//:engine_test                                                           PASSED in 128.7s", "//tools:runtime_source_receipt                                           PASSED in 1.4s", "Executed 3 out of 3 tests: 3 tests pass."], "targets": ["//:engine_test", "//:docs_check", "//tools:runtime_source_receipt"], "workload_exit": 0}

All three engine/docs/source tests passed on signed9e34. This proves the runtime phase/routing regression within model scope; installedI8 software remains unchanged. Root now applied independently reviewed diagnostic proposal164c6853b39737c3d04cbca169174d45c63c580f4fde52988dc58639766c678e. It adds only closed phase/symbolic errno projection through exact tagged exceptions, preserving admission predicates, ordering, OSError/ValueError categories, nested earliest tags, owned cleanup, service argv and limits. It never renders arbitrary error text or paths. Five meaningful new methods cover hostile exception rendering, partial Admission cleanup, manager query failure, nested qualification open and refused cgroup opens. Diagnostics/controller/docs/source tests are queued before any restoration diagnostic action. The prior cause remains unknown.

Git receipt: root | own standard fork, explicit four controller/test files and existing classified note | R-N12/R-N13 | no active executor or service | invocation-local hooksPath=/dev/null and signed commit; Original index untouched.

## Actual session refusal and operator handoff — 21:59 UTC

All eight diagnostic/controller/docs/source tests passed on
0e8757bda03e14efe536bd6b157aaaaae5435385 in dbf05e79-9d81-4e5c-ae07-b7905b6b4615;
receipt SHA6f7eddce7605261f73ddff996a54673de102b6280e0690eb58651f26362bb8ff,
evidence SHA6f9bccf6e46ce4327cd887a0dd56bdf7f99a996230c8ca3340122dac92abb5a1.
Actual owned restoration then refused before epoch/manager query/service launch:
operatorinputs/OSError, session-peers/ECONNREFUSED. Capture is retained in private
operator storage; the redacted result is copied into the Original tracker/session
note. The exact bus-versus-manager endpoint remains unknown at this checkpoint.
No daemon cgroup/control socket/database appeared; pristine installation remains.

The Neo operator owns two requested observations: identify the declared OS-vault
unlock binding (role/path only, no factor values), and establish usable Sting
user-session IPC using the Lab's own operational context. Root has not restarted
shared D-Bus, a user manager, agent session or another owner's service. Public Lab
SOP inspection found no narrow repair/binding recipe in its searched scope.
Normal OS unlock and Omux custody/readiness must still be proved independently.

Root applied independently reviewed peer-role refinement SHA
118677740359ea94f71f589f5cdcc5b95c6bbb691dfc5a0b76e5b11b62281635:
fixed bus/manager initial/recheck phase tags only, preserving original connection
order, socket witness and refusal/cleanup. One meaningful regression uses owned
synthetic AF_UNIX nonlistening sockets to prove actual ECONNREFUSED classification,
FD/placeholder cleanup and preserved runtime endpoints; it never contacts a host
bus. Five controller/docs/source regression targets are queued before capture.
No speculative session repair, factor inference or changed admission is added.

Separate native9 timed out under its original budget (9047cd6f, receipt SHA
48feccb2542c7505567827215f1ddb266840c7635e85d1fb467a77bbe0a60fc1),
with owned empty cleanup and input reverification. Schema10 is closed; no retry,
cache adoption, native CLI/resume/accepted-history/live handoff claim follows.
Zero retained enrolled accounts. All goal acceptance and publication states remain
incomplete; source models and installed Locked control keep their exact scope.

Git receipt: root | own standard fork, explicit two helper/model files and note |
R-N12/R-N13 | prior payload ended/no active resident | invocation-local hooks
bypass and signed commit; Original index remains untouched.
