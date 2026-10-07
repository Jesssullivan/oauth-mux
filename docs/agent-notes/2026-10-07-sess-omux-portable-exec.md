# Portable Linux launcher implementation — provider-free continuation

Authority: the user-authorized Omux implementation and provider-free October 6
native/browser checkpoint; repository AGENTS.md; R-HOOK-CONVERGENCE-20261004,
R-N13. Carrier: [TIN-5338](https://linear.app/tinyland/issue/TIN-5338), with
installation [TIN-2063](https://linear.app/tinyland/issue/TIN-2063) and continuity
[TIN-2057](https://linear.app/tinyland/issue/TIN-2057). Product direction remains
[the active reset](../plans/omux-native-account-lifecycle-reset-2026-10-02.md) and
[the continuation](../plans/omux-native-browser-continuation-2026-10-06.md).

## Trigger and bounded change

The source of the previous portable shell launcher demonstrably creates a
child for command substitution before exec. The ordinary 72e0 native test
observed exact completed status JSON and exit zero, but nonempty ASCII stderr
failed its unchanged gate. Whole-workload process samples reached 512 and an
exposed max event increased; they attribute neither stderr nor old incidents.
The earlier 6616 observer failed to fork before executing its status CLI.
[The receipt](../tracker-updates/native-diagnostic-0412-2026-10-07.json) preserves
both failed gates; none proves replay, retirement, preservation or cold resume.

Replace only the portable Linux shell launcher with a fresh static, no-libc
Zig exec trampoline. Bazel generates a trusted template module from the exact
compiled ELF; packaging and verification compare every byte plus the canonical
256-byte loader/role/channel record. Source review required NONBLOCK on owned
opens, held procfs validation, a zero-size GNU_STACK to preserve inherited
stack limits, and terminal-only SIGPIPE masking for fixed refusal status.
No host loader, shell fallback, cap increase, native predicate relaxation,
provider access or session-store mutation is introduced.

## Ownership and reviewed files

Root adopted excluded proposals sequentially into the existing root-owned
`codex/omux-portable-exec-20261007` worktree based on main
`e4e644cd97343d53d3dc08664f5c0914ab173b99` (tree
`bfd67a0dba57a2d03bd3985a994b323ebc0c7b04`, identical to signed #528 source).
The original mixed checkout/index remains outside this adoption.

- Core: `delivery/linux_launcher.zig` and
  `delivery/generate_portable_launcher_template.py`.
- Wiring: `tools/runtime_zig.bzl`, `tools/rules.bzl`, `delivery/BUILD.bazel`,
  `delivery/rules.bzl` and `delivery/portable.py`.
- Meaningful execution/model checks: `delivery/linux_launcher_recorder.c`,
  `delivery/test_linux_launcher.py`, `delivery/test_portable.py` and
  `delivery/test_generate_portable_launcher_template.py`.
- Nested custody bootstrap: retain the virtual runfile path with `.absolute()`
  rather than resolving into physical source. Fresh isolated Python cannot
  inherit its parent's preloaded module. All custody acceptance checks remain.
- Delivery documentation: `delivery/README.md`.

Sol 6.1 core, wiring and test authors proposed separate owned file boundaries;
independent registry and selection reviewers source-cleared the final proposals.
Root is the sole execution coordinator. Source clearance is not execution proof.

## Initial verification order and limits

1. Declared launcher formatting.
2. Generator models, actual compiled launcher predicates, portable archive
   models, docs and source receipt under unchanged aggregate containment.
3. Surrounding declared packaging/staging/import/relocation regression checks.
4. One justified fresh installed native attempt, preserving strict stderr,
   native identity/history, replay, retirement and cold-resume gates.

Initial native template/model execution is Linux x86_64 only. The parser and
generator model both machine types; AArch64/Darwin installed proof remains
unrun. The recorder deliberately replaces the loader and uses a sentinel
backend. It establishes the exec boundary, not genuine backend/native
continuity. Final loader/backend path lookup is not an atomic held-byte
security boundary. FIFO replacement races remain unproved. Existing upstream
development stage shell tiers preserve alias basenames while changing initial
argv0 spelling. No whole-stage shell-free or raw-original-argv0 claim is made.

Yoga's fresh QUAL/INSPECT passed, but VERIFY refused a nonobject registration
row. No closure copy, browser installation, human toolbar consent or native
proof followed. Home Manager offline evaluation remains unproved; PZM/GF is
held. Live providers, accepted history, stock Codex, same-process live handoff,
Darwin, publication and achieved SLA remain outside proved scope. Five scoped
parent passes and six open gates remain; elapsed time closes no gate.

## Execution receipts

Formatter epoch `4e2ab760-1280-4677-b6da-f382b3eef8c2` finished 0/0 with
empty descendants. The new formatter was initially refused before unit start
because the closed guard admitted only prior root formatter tuples. A reviewed
exact standard-only tuple and refusal models admit this one source file without
changing caps or other profiles.

Targeted epoch `77e9da46-31db-4030-b018-63c66e6a427f` finished 3/3, empty,
with six of seven targets passed: compiled static launcher, generator models,
portable archive models, launcher formatting, guard models and source receipt.
The only failure was the new note's missing authority classification; its map
entry is corrected. Whole-workload samples peaked at 345, with no sampled
512 or exposed max-event increase; terminal counters were unavailable. These
sampled observations carry no individual-process or historical attribution.
See [the receipt](../tracker-updates/portable-exec-2026-10-07.json).

Regression epoch `9b69bca2-e259-4cff-b408-adda3b9ced9d` finished 3/3, empty,
with eight of eleven targets passed, including actual portable Omux/Qt/HTTPS
relocation, compiled development staging, direct-exec C fixture, delivery,
private-session process models, corrected docs and source receipt. Three
failures were outdated fixtures: the shared dev-generation valid runtime
omitted required launcher metadata, and the observer invoked Bash on the new
ELF. Reviewed fixture corrections add independently declared metadata, invoke
the ELF directly and retire the unused Bash argument. Their original custody,
tamper, stream and exact FD2 record assertions are unchanged. Failed epochs
remain preserved. Correction epoch `bb7c913f-bb2c-4070-8375-6d9145c24639`
finished 0/0, empty, with all five targets passed: both generation suites,
the observer, docs and source receipt. This closes the fixture correction,
not an installed native acceptance gate.

Installed native/browser gates remain pending; real relocation is not native
continuity or visible browser proof.

Root is preparing a signed source-only delivery after these scoped checks.
Inspected Home Manager Git hooks are advisory under R-N12; per-invocation
`core.hooksPath=/dev/null` avoids duplicate unqualified project/credential
checks. Global hook configuration remains unchanged. The declared aggregate
checks and independent Git signature/head/tree inspection are the traceable
alternative; normal branch push and exact-head reviewed merge remain required.

## Fresh clean-source native checkpoint — 2026-10-07 03:03 UTC

Provider-free epoch `9f286027-f277-4f91-9097-468574b76d4a` used signed, independently verified clean source `f3684f1ae6e572bd40686dfd4cd4c8e23e494a3c` and the unchanged sealed `0094334d…` runtime input. It ended `3/3`, empty descendants, no controller failure or rejection. Docs and runtime source checks passed; the installed legacy native TUI check failed at `resumed-preservation`, with `resume-retained-config-predicate/resume-retained-config-changed`.

The exact test order reached original native app-server seed detach, native state preservation, clean original exit, fresh-process cold resume and the strict settings checkpoint. The subsequent exact retained configuration/capability comparison refused. This is progress within a failed operation, not a completed ordinary-resume acceptance gate. Resumed detach and durable inspection were not reached. No accepted work or provider calls were introduced.

Raw receipt SHA256 `312d8be5ca74700db7913b5f4a4c86725aec064207c45d58b2c5463cdd98b24b`; evidence manifest SHA256 `fa0b81c0807d33b44141cb2c3ea1d4b9067a936957d551e483e993c86a986550` preserves nine files/216946 bytes. Aggregate workload sampling reached 512 tasks and observed an exposed max-event increase; terminal cgroup reads became unavailable. These observations have no process or historical-cause attribution. Caps remain 4 GiB, swap zero, 512 tasks, two CPUs and 1200 seconds.

Independent final source review cleared all 24 PR529 files without a blocker or product-claim promotion. The frozen source receipt remains a pre-source-delivery snapshot; this current note/receipt records the later failed native operation. Next: inspect exact native configuration-write semantics before a fresh operation; never weaken preservation predicates or mutate the sealed runtime. Parent remains incomplete: five scoped historical passes, six open gates; Yoga toolbar, Home Manager offline evaluation, stock Codex, live handoff and Darwin remain unproved.

## Native startup fixture correction — 2026-10-07T03:10:04Z

PR529 merged as verified `e49acf2e0521dbd739f57d35d4a64ea6e403d4c7`, sole parent E4 and exact C2 tree `21b45255f28bc1d4933242cd6bd602670166c021`; source branch retained, protection unchanged. Existing TIN-5338/TIN-2063/TIN-2057 comments preserve all previous bodies and now have exact readbacks for merged source and failed9f286.

Source-qualified review found one-time TUI startup bookkeeping. Retained candidate upstream `00c972ed5d6ff6499317fd41b7f23605b8e6850d` with patch `2e5542c5f6a44e3a8dd38b4a4093d1735ff19771721b05fc51f55b475b1a8d46` and full inventory `3400115fae8ef204f2ce085880b40887bcb14e2080236ba87a34be9b14fe7d3b` calls `screen_reader::initialize` in `tui/src/startup_orchestration.rs:327` before resume. Without a user `[tui].screen_reader_detection_done` value, `screen_reader.rs:95` writes `true` and atomically serializes the config even for a negative/timed-out probe. App-server seed startup does not take this path. Source SHA256s: screen-reader `4bdfe71be44424b5578d6603faad231ddc5b204ced4852284d26118f79dac459`, startup orchestration `1cef2260614c45550332a53c2fee5f69544841196da74d973335088027802b1b`; prepared receipt `23aaebd33bb3d9fea5a6eeae3051d9d38f49d0107648829f0c5018fcfb051b2e`. Native tests in the inspected source verify that an existing marker skips both probing and writing; those tests were read, not executed here.

Two independent reviews source-cleared initial isolated `[tui]\nscreen_reader_detection_done = true\n` in both ordinary and retained legacy fixture configs before integration/baseline capture. Proposal SHA256 `b41bacb17a0823ddf5992394658882d4a7e876149c32a1f192701f8b515ee820`. Only two comments and that initial literal per fixture change. All exact config/capability equality, original rollout byte prefix/inode, identity, ordinal, policy, replay/status, sealed ledger and no accepted-work assertions remain. Runtime009 is unchanged. The failed9f286 conjunction cannot exclude another config/capability change; this correction is not an RCA or PASS. Source is unexecuted pending one fresh contained provider-free checkpoint.

## Startup-marker installed checkpoint — 2026-10-07T03:23:14Z

Signed clean `2bd9942f34450ec1cf245674aaafecf32425abbb`, tree `c1a44da7176a2feed993afd241465f3bae62f031`, sole parent verified PR529 merge `e49acf2e0521dbd739f57d35d4a64ea6e403d4c7`, is pushed as draft PR530. Independent six-file source review cleared unchanged preservation predicates and current evidence chronology; source records freeze the facts before execution.

Fresh provider-free `ac14f5fa-d87c-446a-823d-12ef6b022153` ended `3/3`, empty descendants, no controller failure/rejection and retained009 reverified. Docs/source passed; native failed earlier at `cold-native-resume/resume-owner-endpoint/resume-endpoint-deadline`. It did not reach resumed config comparison, so actual bookkeeping correction remains unverified. Raw receipt SHA256 `278362fd5786f884041b0f2a946658ea8ac86ea817c2226b3ae3bbcdef5798e4`; evidence manifest `5f9b2c448e21dae4467da3527d68a127cd2e41e63b8e1e0f18dbb2f87b8007eb` preserves nine files/216908 bytes. Whole-workload sampling reached512/exposed max-event increase, with no individual attribution. A later operator census found the already-cleaned cgroup absent; no role-specific counts were captured. Limits unchanged; no automatic rerun.

Scope clarification: this legacy lane creates a provider-free empty thread through the candidate's native app-server, then uses the ordinary TUI cold-resume command. It does not establish initial ordinary TUI launch or accepted-conversation/tool/approval preservation. Native `--strict-config` excludes shared-daemon auto-start. Exact frozen-matching embedded source prepares owner admission through `spawn_blocking`; preparation can fail while the native processor remains alive. These are code boundaries, not a cause for ac14 or historical exhaustion. Next diagnostic proposals remain excluded and unimplemented.
## Verified startup-fixture delivery and next bounded diagnostics — 2026-10-07 03:45:25 UTC

PR530 merged as server-verified `0b0df5d6afbe25fd596944636571c63cae5ab72f`, sole parent `e49acf2e0521dbd739f57d35d4a64ea6e403d4c7`, exact signed C4 tree `5a0a97a60f3ba4219beca7eab9a32dcbf747c56d`. Signed source `524febc15ad66b106dbaf3c9a45e86569df67b0b` was independently source-cleared. Final clean-source docs/source epoch `f84a5b2e-6638-4c52-9a2a-b76f9b9bd5c6` passed both targets, 0/0 with empty descendants and no controller failure/rejection. Its raw receipt SHA256 is `e03a4996a57bbd42c58741318f39f96c13e963b38f7b97ec990216c9dcb24023`; evidence manifest `c9414e027683730b66d7d8f01f535a37a03466cfc7f67a594f0019b341a9f94c` preserves seven files/215741 bytes. This is source delivery, not native acceptance. The last installed native result remains failed ac14; no native rerun occurred for C4.

Root's clean owned continuation branch is `codex/omux-bounded-proof-diagnostics-20261007`, based on that verified merge. Implementation/review agents write excluded UNAPPLIED proposals only. Proposed failure-only census retains held genuine-procfs directories and pidfds for exactly five fixture-created roles; namespace and deferred-interrupt handling are independently reviewed. It emits closed role/state labels and bounded thread counts, never process names, paths, identifiers, raw native output, configuration or history. Counts provide neither executable admission nor a cause for historical task pressure. The planned diagnostic budget fits the original 90-second private-session timeout; aggregate resource limits and all native preservation predicates remain unchanged.

The Yoga proposal adds bounded raw registry-shape hints while retaining exact registration/reference equality and independent NAR rehash. Null, missing or nonobject rows remain unaccepted; hints establish neither physical absence, corruption nor store-import authority. Destination capacity, protected importer/system-manager authority and shared Nix-daemon containment remain separately unproved. No copy, activation, provider use or human toolbar proof is authorized by these read-only observations.

Order: independently review final proposals; root applies them sequentially; one serialized contained model/owned-child batch; only after successful verification, one fresh provider-free native checkpoint. No automatic repetition or cap increase. No payload is active at this record. TIN-5338/TIN-5421 retain native acceptance; TIN-5442/TIN-2720 retain installed browser acceptance. Parent remains five scoped historical passes/six open; the original objective is incomplete.
Both final artifacts are applied only in the owned continuation tree, untested: native census SHA256 `8497fd38c0f36928de31f8372eb47e59e666bedd1e4405732ae8750699c69927` independently cleared by registry and tests reviewers; Yoga shape SHA256 `69d79d4b03e4fc4a1e37d69ad127f88e32d993bcc38bc21eb51524f64c32af61` independently cleared by selection review. Added meaningful predicates include actual saved-FD EBADF teardown, mid-read and between-role deadline expiry, PID/parent/UID/directory/namespace drift refusal, and deferred interrupt same-object/assigned cleanup anchors. No declared native acceptance predicate changes. The [bounded diagnostic receipt](../tracker-updates/bounded-proof-diagnostics-2026-10-07.json) records the serialized targeted batch and subsequent one-attempt native order.
## First census batch and deadline correction — 2026-10-07 03:53 UTC

Epoch `3710749b-b415-4225-9763-dc701653007b` ended 3/3, empty descendants, no controller failure/rejection. Four of six targets passed: Yoga shape, original CLI failure models, docs and source inventory. Both census targets failed the same already-expired-deadline model. Actual owned-child/FD-teardown cases completed within the failed suite; full target acceptance remains failed. Raw receipt SHA256 `4397366cf6da0c9da48abe9a0dcf6f3350bae850ec7d18af2a476910cd75f42b`; manifest `1ade025706cdd57541723a6ee9cd183baddc40f61065c96a6c54987ee7ffd63d` preserves fifteen files/224729 bytes. Aggregate sampled peak302 and no exposed max-event increase carry no attribution; terminal counters were unavailable.

With a valid but already-expired absolute deadline and no enrolled entries, `failure_records` previously skipped its per-role checks and returned unchanged not-created/profile states. Root adds only `self._check(deadline)` immediately after `_budget()` inside the existing closed fallback. This corrects the evidenced implementation and preserves all model assertions, states, bounds, process behavior and outer deadlines. Independent review precedes an affected-only two-census/docs/source rerun. The failed epoch remains retained; no native application has run in this continuation yet.
## Corrected diagnostic predicates passed — 2026-10-07 04:00 UTC

Epoch `a92d4563-8465-4122-b208-681a8ddd599f` passed all four affected targets, 0/0, empty descendants, no controller failure/rejection. Raw receipt SHA256 `d33696828ab66c1acabe67dd95f565c4216027e9ca5922f33d55e2a5c98f95b0`; manifest `d3d75e0860e2bbb7bfa1a1ce54317950fcf2d6e7fcce4886534dbba2eea4fe48` preserves eleven files/218807 bytes. Both census suites now pass, including isolated actual owned-child counts, retired selectors and saved-descriptor EBADF teardown. Earlier3710 failed evidence remains distinct. Unchanged Yoga/CLI models retain their passing3710 scope. Aggregate sampled peak324/no exposed max-event increase has no process attribution; terminal counters were unavailable.

These scoped checks establish diagnostics only. Root will freeze a signed clean source snapshot for one fresh existing-environment provider-free legacy native attempt. Retained009, aggregate caps, Tokio async-worker setting and every native preservation predicate remain unchanged. A reviewed public-source lead identifies an independent non-Tokio blocking pool; its ceiling is not an observed count, the dependency control remains unapplied and no prior failure cause is asserted. Parent remains five scoped passes/six open; native, Yoga and Home Manager gates remain open.
## Clean-source native failure census — 2026-10-07T04:08:51Z

Signed clean C5 `e54257e8887e4d9921b87e311242f01a5f56e9c7`, tree `5d8629b5b9acbc2d27fedab7298c64a0bb05b7f9`, sole parent PR530 merge `0b0df5d6afbe25fd596944636571c63cae5ab72f`, is independently source-cleared and pushed as draft PR531. Per-invocation hook bypass for this root-owned commit/push uses the existing R-N12 traceable alternative: contained Nix/Bazel checks and independent signature/head/tree/clean readbacks. Global hooks and remotes remain unchanged.

Provider-free `81e76dcd-a457-42d6-b05a-1bd8d50ca0d6` ended3/3, empty descendants, no controller failure/rejection, sealed009 reverified after cleanup. Docs/source passed; native failed at `native-seed-history/seed-history-attachment`. It reached provider-free seed/full-read metadata and failed the exact original attachment check before detach or cold resume. The current category does not distinguish discovery-RPC refusal from full attachment equality failure. Raw receipt SHA256 `8b7b91c3ef7a2cd3662c2e3501f7bee909b8f944563b0563953a77755f25a8e5`; manifest `73e173942b291937ad3c312e00346619c4a53e52225cb22b3604bcd5d423df54` preserves nine files/218524 bytes.

The new census emitted actual held-role snapshots before cleanup: self4, daemon24, keyring5, native-bootstrap27, native-resume not-created. These are failure-time snapshots, not peak/pool counts, executable authority, a whole-workload sum or a cause for this or earlier failures. Whole-workload sampled peak389 and an exposed max-event increase were observed; no512 sample, terminal counters unavailable, no attribution. Resource caps and existing environment are unchanged.

Full native acceptance remains open. No dependency pool control is applied and no automatic native rerun follows. Source-only follow-on reviews target closed attachment-RPC/reference distinctions and explicitly bounded Bazel controller work using exact version sources. Yoga registration/content and human toolbar, Home Manager evaluation, stock support, accepted-history, live handoff and Darwin remain unproved. Parent remains five scoped passes/six open.
## Reviewed next comparison and controller scheduling — October7

Root applies seed diagnostic proposal SHA256 `842ebdc1f31443d59d263e4b5bb5b558bc6842897d533e40f0f2d52f1ffc9eba` and standard controller proposal `95cb22114e96208d2de21ad8916da3f45663308cd104162b18120e279c3ce992`, both independently source-cleared by registry and tests reviewers. Both remain untested at this record. The fixture keeps PID short-circuit, one discovery RPC, unchanged validation, full equality once and exact require; seven finite false-only stage/difference labels expose no native data. Ordinary projection faults retain failure; controls reach the original cleanup.

The standard guarded Bazel9.0.1 constructor now explicitly sets `--legacy_globbing_threads=2` and `--experimental_fsvc_threads=2`, with matching cache execution fields and unchanged caller restrictions. The [version's glob setting](https://github.com/bazelbuild/bazel/blob/9.0.1/src/main/java/com/google/devtools/build/lib/pkgcache/PackageOptions.java#L132-L143) defaults100 and controls ForkJoin parallelism, allowing compensation threads; it is not a strict two-thread maximum. Its [fsvc setting](https://github.com/bazelbuild/bazel/blob/9.0.1/src/main/java/com/google/devtools/build/lib/buildtool/BuildRequestOptions.java#L398-L412) defaults200 and feeds a fixed filesystem-checker pool, bounding active workers per checker. Loading already nominally follows JVM processor2. These are code-configured settings, not measured worker counts or a failure cause.

Actual main-path cache metadata is independently reviewed: both new fields enter the standard profile before stable fingerprinting. Separate SDK/site constructors and metadata remain unchanged; site mod cannot accept fsvc. Yoga/dependency/browser/formatter constructors inheriting the standard graph receive the settings. All aggregate caps, cleanup, deadlines and native assertions are unchanged. Lower parallelism may cost setup latency; deadlines remain acceptance bounds. One follow-on model batch precedes any fresh native operation; no speculative application blocking-pool control is added.

## Fixed controller and comparison model verification — 2026-10-07 04:25 UTC

Contained epoch `72c5db5e-f94c-47d5-907f-bac7b304107a` passed all seven targeted checks: finite seed attachment diagnostics, native role census, guard command policy, guard cache, dependency profile, documentation and source receipt. It ended 0/0 with empty descendants, empty cleanup and no controller failure/rejection. Raw receipt SHA256 `bab569e8ddb05ec8106021bd51a7d52eee9dbac0df5de12ae2b4e1d78462cf62`; evidence manifest `7eec9be61cbba1d9acb1fec103eee232c24a859b8d8ac44f3f206a5e59ecba40` preserves seventeen files/222313 bytes. The actual standard cache profile records glob parallelism2 and fsvc workers2. Sampled whole-workload peak251/no exposed max-event increase has no causal attribution; terminal counters were unavailable.

The model tests preserve the PID short-circuit, one RPC, exact full attachment equality and original exception/cleanup behavior. Aggregate limits, sealed009 and native preservation predicates remain unchanged. Prior81e native failure remains the latest installed result. Source/model verification does not establish native resume, installed Yoga browser consent, a measured SLO or a failure cause. Root now freezes this source for one fresh provider-free native checkpoint; no automatic retry follows.

Original repository witnesses are distinct: staged Git tree `7a96ce176bbd958f7bf5575df14b3fa2506bac55` and index-file blob hash `b080364090fc804487e6a092d884cfa6a463aa99`. Do not call the latter a staged tree. The existing mixed index is preserved; implementation staging occurs only in the owned continuation worktree.

## Terminal native and Yoga checkpoint — 2026-10-07 04:52 UTC

Signed clean C6 `674c44bf3bca7b8776f3a98da35b82315698ea97`, tree `be2fa93fb538f62db028dd4d3baa86e7d895a07d`, was independently source-cleared with exactly seventeen PR531 paths. Provider-free native `e761fae3-bbf4-4c68-af4c-23075c43bab7` ended3/3, empty descendants/cleanup, null controller/rejection and sealed009 reverified. Docs/source passed; native failed at `cold-native-resume/resume-owner-endpoint/resume-terminal-exited`. It reached original seed/full-read, exact attachment, selected detach, native state preservation and clean original exit before the resumed terminal exited without the required endpoint. Complete resume, resumed settings/config comparison, second detach and final ledger acceptance remain unproved. Raw receipt SHA256 `db0f8c2670223fe8cc35bde7b5ed40ce741701d6991ffbc924f731be0c9e49b7`; manifest `f3cf9cb731b7dca55c2a788ab8bb4359d1df01c6b866fc6bbe14464158ae967e` preserves nine files/219075 bytes. Actual failure-time roles were self3, daemon24, keyring5, bootstrap retired and resume retired. Sampled whole-workload peak509/exposed max-event increase provides no cause or individual peak attribution. No automatic rerun or application pool knob follows.

Fresh C6 Yoga qualification `0deaf9e1-b646-4050-b425-eb7c080da3fc` and inspection `d2b8b025-9ae0-4bc6-8882-6309b8372b25` both ended0/0, empty descendants/cleanup and null controller/rejection, with source verified after cleanup. Qualification receipt SHA256 `92358f5d5acc4605b2cf00b018e81ce5cbc8cc74d45ea27fbd2e7ca281c065ec`; canonical qualification SHA256 `ff84bb9205565656e2ba6abe1dbaacf943153b0f4e48129695797910d875c753`. Inspection receipt SHA256 `5c24160927cfd57015723aa370a1d10ef130f82bc2f71751d56c98c77783a7f2`: daemon client trusted true, capacity remains null. The qualified executable pathname includes Determinate Nix3.22.3; a semantic version command was not run.

One verification `234a0467-0a25-4b17-8598-d8ad1844ba1b` ended2/2, empty descendants/cleanup and null controller/rejection, refusing `destination-registration-content/row-object` with rowKind null. Exact raw requested472 map: object3, null469, missing0, unsupported0, extra0. No destination content was rehashed or registration accepted. Receipt SHA256 `672bd69963cecc33a41f93920fb2a07b6c23b03b742fdb1af2a1b56c65026bd0`. Null registration JSON does not establish physical absence, corruption or import authority. Capacity, destination-owned containment, remote cleanup, browser inputs and actual human toolbar consent remain unproved; no store import, activation or provider call occurred.

Exact retained source supports provider-free BrokerManaged startup and bypasses the native login restriction; no authentication-based fixture change is justified. The frozen lock excludes async-global-executor/async-std, ruling out their environment control. Remaining blocking-pool policy requires package/features/first-init/starvation qualification before use. Independent source-cleared HM deadline and same-daemon Yoga proposals remain separate next work, not installed evidence. The parent objective remains incomplete with five scoped passes/six open gates. No measured SLO/SLA, stock support, accepted-history, live handoff or Darwin claim changes.
