# Native evening implementation evidence

This is the implementation receipt for the
[evening push](../plans/omux-native-evening-push-2026-10-03.md) and
[checkpoint ledger](../../.goal/omux-native-evening-2026-10-03.json).
The interval is `2026-10-04T00:22:08Z`–`2026-10-04T05:22:08Z`.
The native reset remains experimental and unshipped. The morning partial
checkpoint, pause snapshot and historical release evidence retain their scope.

## Current receipts

| Scope | Invocation | Observed outcome and limit |
| --- | --- | --- |
| Initial formatting | `b56bc173-9935-49a9-83f7-7553e4c28e42` | Locked Nix/Bazel formatted only Codex native control, native probe, reliability and vault files. |
| Initial integration formatting | `a2c1fa23-1966-4739-a864-4f8e4b6b1149` | Formatted request/mutation authority, engine/acceptance, control and reference. Authority reservation refinements afterward require another formatter gate. |
| First narrow runtime/installer/doc batch | `8300a582-b819-48a4-9697-746e945848b5` | Five of six targets passed: Codex, reliability, vault, installer and docs guard. Documentation check failed because the new tracker JSON was not declared in its runfiles. BUILD data declaration corrected; both documentation gates passed in the later combined batch. No native-probe, actor, daemon or platform promotion from this batch. |
| First SPA journey epoch | `c226142a-7462-4d59-ad70-aa41c5a4a81e` | Five fresh SPA tests passed: reference, unit, Svelte, archive and Chromium smoke. Browser checked mobile/desktop layout and generated journey links. Imported bundle remained `f6467e0f6ebfb0a6ceffeb9be9eccdf006f4d26968caa2a1e1eaf8ae61c44c74`; a later producer contract update requires another import and reconciliation. No deployment. |
| Combined authority/native/daemon/actor batch | `89f7b168-5501-459e-b9d1-c4cc1d957b2e` | Eleven of twelve targets passed: request/mutation authority, engine, daemon, native probe, reference, formatting, both documentation gates and both Qt transport/runtime-path tests. The first new actor import test failed because its fixture read `accounts[].account_id` instead of public `accounts[].id`; the other 194 embedded actor predicates passed. One acceptance-only helper line was corrected. |
| Actor retest, current producer and Qt build | `1e3d70b4-a16c-4c05-a8fb-c305925b791c` | Actor acceptance passed all 195 embedded predicates, including held imports and actual encrypted-row expiry while the queue remained busy. Current reference and Qt control built successfully. No live provider or installed Darwin claim. |
| Qt offline self-check | `70a2d17d-f98d-49aa-87cc-0c5075ef84b0` | Actual rebuilt controls constructed, processed an event cycle and returned `OMUX_CONTROL_SELF_CHECK_OK`, with no daemon/source connection. Interactive desktop and SwiftUI proof remain separate. |
| Current source reference digest | `6c63a93b-cd20-4a7b-a5db-3c67c1c0e266` | Actual producer output is 16,008 bytes, SHA256 `08d57858b766c39ead4700f25897706175a4a96ba00da97799d1cb5e513442b6`. Corrected enrollment/repair/reliability summaries retain missing-hook and live-proof limits. |
| Exact SPA import and final journey epoch | `74b9287e-394c-4dfa-a952-f98a27f874e9`; `8708b5c7-1acb-4f2f-be86-b293a97d0ddc` | Declared importer consumed exact current producer bytes and checked digest. Five fresh reference/unit/Svelte/archive/Chromium tests passed, zero skipped/failing; production build/archive dependencies passed. Includes final resume wording and guided links. No deployment. |
| Current Linux package epoch | Tool session `27534`, `2026-10-04T01:07:03Z`–`01:08:52Z`; invocation ID unavailable | All three targets executed freshly. CLI and isolated installed-custody predicates passed; relocation failed in its local HTTPS verification subprocess, whose retained fixture exception does not classify the cause. Archive SHA256 `1cb5a98d233327c6a304198c17bef3ce318f8069c1a8aed7cd2d2748b942b411`, 59,774,909 bytes, 138 artifacts. Later client/runtime fixes require another artifact epoch. |
| Mistaken formatter target | `8ba1da94-3555-4ec2-ae03-f130f8f0af40` | Failed before execution: root selected nonexistent `//:format`. Correct target is `//tools:format`; no formatter/compiler action ran. |
| Corrected second-wave formatting | `4af4a607-a64d-4eb6-af4a-bbc46227876c` | Declared formatter passed for engine/acceptance, native probe, setup, storage and test-only TLS probe. Later fixture-only corrections need another format gate. |
| Second-wave runtime and package batch | `21d76860-e353-4845-bfa6-b379f3ee1d9b` | Fourteen targets: ten passed, four failed; eleven fresh and three cached. Fresh passing gates include documentation, formatting, native probe, real SQLite oversized completion, CLI, installed custody and strict TLS relocation. Setup/engine/daemon failed a 1,380-byte test-arena leak; actor additionally failed its new native removal installation fixture with `SocketPathTooLong` (199 passed, one failed of 200 predicates, plus inherited leak). Later fixture corrections and passing gates are recorded separately below. |
| Second-wave Linux archive | Produced under `21d76860-e353-4845-bfa6-b379f3ee1d9b` | SHA256 `e3ea87845b2e768edd6f16db7b0c8344dab19024fe8019c771b5e0bcb80ec59b`, 59,779,255 bytes, 138 artifacts. Installed custody passed in 15.5 seconds; relocation passed in 15.6 seconds, requiring typed TLS rejection for an untrusted certificate and exact body for the trusted case. This does not recover the original TLS failure's cause or make the overall runtime batch pass. |
| Fixture-only correction formatting | `909e80c9-a0c9-4409-a361-1f12c5e8a163` | Declared formatter passed after constructing complete setup-fixture options before copying its arena, and selecting a private shorter native-removal fixture root. Leak detection and the production protocol remain enabled. |
| Corrected runtime and documentation gates | `829423a4-b40c-4fa1-a62e-c030cac8615d` | Seven fresh targets passed, zero skipped/failing: setup, engine, actor acceptance, daemon, formatting, documentation and documentation guard. Actor acceptance passed all 200 embedded predicates. Completed `2026-10-04T02:05:31Z`, 97.565 seconds. |
| Full coherent local suite | `524a33ee-3582-4132-8479-37702b89d22b` | All 57 test targets passed, zero skipped/failing: eight fresh and 49 reused from matching input digests. Selected 104 top-level targets (47 non-test and 57 test). Completed `2026-10-04T02:16:52Z`, 282.374 seconds. This is Linux/local proof; it neither compiles Swift nor establishes actual PZM execution or provider continuity. |
| Final candidate metadata/tooling/documentation oracle | `c8fdc62e-a79e-4301-8303-8ad417ee84cb` | Three fresh targets passed in 27.904 seconds. Current metadata is checked against the actual candidate manifest, reviewed source hashes and 107-file producer output. Earlier broad compilation/protocol receipts retain their historical epoch. |
| Manual SSH Darwin recipe retirement | `fa21895c-b451-4d67-8129-e4c5f6589876` | Three fresh targets passed: 23 deployed-runner cases, 12 worker cases and documentation. Both `darwin-build` and `darwin-vault` reject before archive, operator configuration, transport or custody access. Linux proof and exact historical Neo diagnosis/cleanup remain available; the declared Darwin vault action is retained for REAPI. No host calls. |
| Remote Linux resource and invocation binding | `2b3748a1-fda3-43e7-9b60-616ee8aa13e2` | Thirteen fresh worker cases passed. The single remote batch Bazel command now uses `--jobs=4` and `--invocation_id` equal to the canonical proof UUID. This validates command construction; actual remote execution requires its own receipt. |
| Future-window formatting and direct domain gate | `8b90859d-7282-44b1-8efb-4f4c29c386a7`; `a4e6e57c-d3c0-4c07-9853-fd37316fe9a2` | Formatter passed; domain, format and docs executed freshly and passed, with docs guard reused from matching inputs. All 33 embedded domain predicates passed, including unavailable future capacity before the start and one deduplicated bucket at the boundary. |
| Full local build with future-window correction | `605e36e7-22bd-47ea-af15-8f831fedc2b4` | All 104 selected targets built successfully; 34 actions, 142.995 seconds, completed `2026-10-04T02:37:30Z`. Local Linux compilation only. |
| Final coherent runtime/helper suite | `45130b54-8c39-4ea7-97f8-1251913e18cf` | All 57 test targets passed, zero skipped/failing: 12 fresh, 45 matching-input cache results. Actor passed 201 embedded predicates. Includes the future-window correction, retired Darwin SSH recipes, remote Linux resource/invocation binding and manifest-bound package-alias helper. Completed `2026-10-04T02:40:02Z`, 50.343 seconds. Later diagnostic-only helper refinement needs its focused gate. |
| Current Linux package identity | Produced under `605e36e7-22bd-47ea-af15-8f831fedc2b4`, freshly tested under `45130b54-8c39-4ea7-97f8-1251913e18cf` | SHA256 `aed5dce3535e10161594152f10c9e6be2d2a0a0ea71da060b4ed4002077ea3ee`, 59,779,390 bytes, 138 artifacts. CLI passed in 1.2 seconds, isolated installed custody in 11.6 seconds, strict TLS relocation in 10.2 seconds. No service activation or live provider proof. |
| Current artifact/reference byte reconciliation | `e1123e64-5c8d-4976-927b-7e2b31d54d2f` | Declared locked Python through Bazel read actual output bytes. Producer and SPA import are both 16,008 bytes with SHA256 `08d57858b766c39ead4700f25897706175a4a96ba00da97799d1cb5e513442b6`; current archive matches `aed5dce3...`, 59,779,390 bytes. Existing five fresh SPA gates retain their unchanged bundle scope; no deployment or new provenance authentication. |
| Final diagnostic/analysis-decoding helper gate | `d513e87c-411a-44ec-8393-dddbd8c1dcca`; `7807e314-6698-424a-b999-306391927ae6` | All 31 adversarial cases passed freshly; final documentation passed freshly and helper result was reused from matching inputs. Private exception text is suppressed; omitted proto3 analysis values decode as empty strings while execution receipts remain strict. This does not accept the real Darwin graph, whose final outside-closure rejection is preserved below. |
| Final source/reference/documentation build | `606517ce-25b1-4c66-8a32-18b1b012ba98` | Source archive and reference built; docs passed freshly and docs guard reused matching inputs. Two tests passed, zero skipped/failing; completed `2026-10-04T02:52:01Z`, 59.443 seconds. |
| Immutable Sting source input | `cb2459b0-d053-4b55-bd80-cd908cf5f4ab` | Declared locked Python copied source archive into a private directory with exclusive 0600 creation, file fsync and hash readback. Source SHA256 `7268df4b666364934fe5a2098768d091e235f59a781a186f7df247f4ea32ca8a`, 3,244,546 bytes. This freeze predates the later C++ action-environment correction; its Sting receipts do not certify that changed compilation graph. |
| Dedicated Sting installed-custody proof | Local `b902ab14-1229-4b3b-85e0-5b3ccbb70942`; remote proof/Bazel `c6f3600c-a728-490b-8219-ee4158f6f179` | Passed: local, graph and remote exits zero. Admitted exact `7268df4b...` source into `.run-SYhDgS0o`; bootstrap `02:56:43Z`, graph `02:56:50Z`, analysis complete `02:58:11Z`, action execution `02:58:14Z`, graph complete `03:02:39Z`. Returned composite was observed by `03:04:33Z`; no exact terminal timestamp is emitted. Current workspace cleanup and `current_cleanup_result` both `removed`. Linux/x86_64, numeric kernel 6.12.0. |
| Sting independent artifact/log identity | Returned by `b902ab14-1229-4b3b-85e0-5b3ccbb70942` | Remote artifact SHA256 `aed5dce3535e10161594152f10c9e6be2d2a0a0ea71da060b4ed4002077ea3ee`, 59,779,390 bytes, exactly matches current local output. Complete private log SHA256 `0e5ba1ce2c5452ae519cc6c4451a4cda6e326ee9f418eb230a01bc025f4d9afb`; raw log is not public evidence. Scope: actual installed portable daemon/CLI/offscreen Qt, genuine disposable Secret Service custody, process restart/mutation replay/rollback/uninstall predicates. No services, personal vaults, provider access or seamless native continuity. Historical unknown workspaces were untouched. |
| C++ environment fixture analysis failures | `8e4176bd-3477-4b05-912f-7293d23f016e`; `f951ee14-56e3-4a44-a15e-842961d7fd70`; `e9deef33-99e6-4c1c-9f3b-eb1011a2b49f` | Three distinct analysis-only failures: empty feature environment value, private strip-variable API arguments, then a fixture expecting a non-PIC archive where only a PIC archive was produced. Each dispatched zero compiler actions. Corrected fixture uses the public variable API and accepts the configured PIC archive. These are not failed application tests. |
| Declared C++ environment and actual action smoke | `fcb9b12b-dc6f-4cdd-ae5f-2a76883bdd0d` | Passed in 16.021 seconds: five fresh Linux-sandbox actions and three internal actions. Actual C/C++ compile, executable link, PIC archive and strip succeeded despite `--action_env=PATH=/omux-fixture-unavailable-search`. All ten configured C/C++ action environments use the exact declared coreutils directory; assembly, linkstamp and shared-link environments were inspected only. No Darwin execution or application behavior claim. |
| Current C++ graph Linux package/client gate | `db4a0fc4-b715-4d6f-8d73-8f195dadbdc1` | Passed, completed `2026-10-04T03:29:07Z`, 92.389 seconds. Qt control and release archive selected with five downstream runtime-path, transport, CLI, installed-custody and relocation tests. Fifteen fresh Linux-sandbox compile/link actions plus one internal action; five tests reused matching-input results, zero fresh test executions and zero failures/skips. This proves the corrected Linux compilation graph separately from the earlier full runtime suite and frozen Sting source. |
| Post-C++ artifact/reference byte reconciliation | `6c9d458a-f3d0-4f7d-8a25-df004052051b` | Declared locked Python through Bazel read the actual rebuilt outputs: Linux archive remains SHA256 `aed5dce3535e10161594152f10c9e6be2d2a0a0ea71da060b4ed4002077ea3ee`, 59,779,390 bytes. Producer and SPA import remain identical SHA256 `08d57858b766c39ead4700f25897706175a4a96ba00da97799d1cb5e513442b6`, 16,008 bytes each. Sting's installed predicates therefore apply to the identical runtime artifact; its frozen source does not certify the new C++ compilation graph. No repeated SPA tests or deployment. |
| Full build of corrected C++ action graph | `05b19b4d-5976-4e53-ab1d-2aa843ae6731` | All 105 current selected targets built successfully, including the compiler-environment fixture and native C/C++ bridge targets. Eighteen actions: twelve fresh Linux-sandbox and six internal; 602 matching action-cache hits. Completed `2026-10-04T03:38:35Z`, 87.197 seconds. This is local Linux compilation; macOS-constrained targets are skipped, and no PZM action execution or installed Darwin behavior is established. |
| Expanded Codex candidate compile with lost source custody | `0197ea30-4adc-4d3e-9e6e-b4526b2cd8a1` | Failed; started `2026-10-04T03:45:26Z`, completion observed `03:48:13Z`, 162.031 seconds. Nineteen Linux-sandbox actions, two internal, 2,041 action-cache hits. Missing `cloud-tasks` source caused compilation failure; Bazel also skipped cache upload after detecting changed TUI input. Subsequent read-only inspection found source files, module and original tar absent from the preexisting temporary checkout. Seven reported successful top-level targets are not accepted as current candidate provenance. The prior 17 focused predicates and packaged candidate hashes remain separate. No Rust implementation defect is inferred; restore complete verified pinned source at a durable location before retry. |
| Initial durable restoration-tool gates | `78e62e15-97d0-48ef-b2c6-5199366a3e4c`; `a1dc251f-8ae2-4e39-a22b-e474a56dbb58` | First gate passed three targets in 93.313 seconds: restoration and patch oracle executed freshly, tooling reused matching inputs. Stricter root-custody negative gate passed in 29.889 seconds. These are tool predicates, not upstream compilation. Later exact-mode and prepared-inventory checks require their own final gate. |
| Complete pinned source fetch and strict verification | `4a1f7834-d47c-4a77-a497-73cbe5cd41f7`; `bedecf63-91b6-4dde-bae3-cc509742de0c` | Restored source under durable private state, using declared locked Git and CA inputs through Bazel. Exact commit `00c972ed5d6ff6499317fd41b7f23605b8e6850d`, Git tree `6fa1a3767a92ba5d579fcaf724fdce3049c2070b`: 8,497 files, 84,097,652 bytes, inventory SHA256 `db5f14df73a76ca55008742783e9a56c94e60439ab62447e4a8e1ff0d884995c`. Fetch and verification Bazel build phases were 22.744 and 17.465 seconds; these exclude the generator's subsequent local execution. |
| Candidate preparation refusal and correction | `5f204045-a2fb-4736-b031-d5a8b1a4a120`; `70b8ac98-f7f5-455c-a012-4de9bd565a36`; `09b2b08a-113c-4ab5-a6af-31cc8cd20325` | First preparation rejected validation-overlay Git index metadata before writing source. Narrow parser refinement and negative gate passed in 27.919 seconds. Complete preparation then passed: 8,515 files, 84,372,839 bytes, inventory SHA256 `d1516b7ca018277407de37b1af8463ae002e67cab7ac6664ecdbfe6fef9034a3`. Module, resolved lock, Cargo lock and normalized workspace digests matched validation. Successful preparation's Bazel build phase was 17.972 seconds, excluding generator execution. Candidate patch/source hashes remain unchanged. |
| Restored-source eight-target compilation | `f76aed1e-36a7-4f9b-9c16-35cd91e9b4e0` | All eight targets passed; started `2026-10-04T04:10:38Z`, completion observed `04:47:52Z`. Bazel elapsed 2,224.019 seconds, critical path 723.95 seconds; 7,844 reported actions/processes, 1,385 internal and 6,459 Linux-sandbox. Cache-hit count was not reported. Full pinned prepared source and locked upstream Nix/Bazel inputs, four jobs. Compiles core, app-server, config, protocol, TUI, CLI and two schema producers; it does not prove installed/provider continuity. |
| Inherent upstream schema-generation actions | Within `f76aed1e-36a7-4f9b-9c16-35cd91e9b4e0` | Stable and experimental PublicSchema actions each ran only `write_schema_fixtures_from_env`: one passed, 318 filtered. Reported helper durations were 9.33 and 9.32 seconds; merged output does not establish their mode pairing. These are declared build outputs, counted separately from the eight target results and prior 17 broker predicates. They do not rerun the full historical protocol suite or rewrite packaged source fixtures. |
| Post-build complete inventory refusal | `889c08ae-ce97-4e4c-a293-09021263bcd5` | Failed the complete source inventory predicate after Bazel created exactly four convenience symlinks at completion. Read-only inspection found the expected bin/out/source/testlogs links to the current output base; no original source-blob mismatch was identified. A narrow verify-prepared-only classifier must independently verify and count those exact owned links before a corrected whole-source receipt can pass. No link deletion, arbitrary source exceptions or managed guard-hook refusal. |
| Exact post-build link classifier and complete source verification | `581207b2-a589-43b9-818c-d729243656de`; `916e727b-2b7d-43fa-a8be-663f9e325cee` | Final classifier test passed freshly, 7.582 seconds; independent source review accepted exact four names, owned links, canonical targets, redirect/nonlink/extra refusal and separate generated-link counting. Complete post-build verification then passed, observed `2026-10-04T04:57:26Z`: 8,515 tracked files, 84,372,839 bytes, unchanged inventory `d1516b7c...034a3`, plus four separately verified generated links. Its Bazel build phase was 25.263 seconds, excluding generator execution. No output-tree traversal or source deletion; no empty-directory, same-user tamper-resistance or crash-durable tree claim. |
| Final restoration custody gate and read-only prepared oracle | `5ab7f132-975e-4ed0-b082-cd6ebf3ee642`; `d3fae2cf-6921-4c42-bd81-f33a17307481` | Focused gate passed three targets in 27.815 seconds: restoration test fresh, patch/tooling matching-cache. Independent review verified source-root redirect refusal, exclusive no-follow 0600 receipt creation, exact 0644/0755 modes and packaged-original comparison with pinned Git. Read-only prepared verification passed with unchanged 8,515 files/84,372,839 bytes and `d1516b7c...034a3` inventory; its Bazel build phase was 33.239 seconds. No source writes, arbitrary extra-file exceptions or crash-durable tree guarantee. A post-compilation inventory check remains separate. |
| Final coherent current local suite | `cfd57c72-8f91-4c4b-b826-a7316d558d8a` | All 58 targets passed, four fresh and 54 matching-input cache results, zero skipped/failing. Selected 107 targets. Completed `2026-10-04T04:32:00Z`, 220.809 seconds; 64 reported actions. Reported process counters: 19 Linux-sandbox, eight processwrapper-sandbox and 41 internal, with 624 action-cache hits; these counters are not summed as a disjoint action partition. Includes the C++ environment, Arocc generator override and final restoration custody fixes. Actor/domain retain matching-input 201/33 predicate results. Later documentation and candidate validation-receipt edits require focused checks. |
| Final coherent current local build | `69c659e4-2e5a-43a3-8c04-33fe9286c6fd` | All 107 targets built successfully at `2026-10-04T04:33:41Z`, 61.183 seconds. One internal action and 348 matching-input cache hits; zero fresh compiler actions. The preceding full-suite invocation executed the changed actions. Linux compilation only; macOS-constrained targets skipped. No new installed, remote or live proof. |
| Final actual artifact/reference equality | `b6328e77-7e22-453c-8a1e-a1c1415c6d6b` | Declared locked Python through Bazel read actual post-build bytes: Linux archive `aed5dce3535e10161594152f10c9e6be2d2a0a0ea71da060b4ed4002077ea3ee`, 59,779,390 bytes, identical to Sting's installed runtime artifact. Producer and SPA remain identical `08d57858b766c39ead4700f25897706175a4a96ba00da97799d1cb5e513442b6`, 16,008 bytes each. No repeated SPA suite or installed run, and no transfer of the newer compilation graph into Sting's older source epoch. |
| Graph-document link correction | `8b7a0e8f-0742-4f99-862a-c5fece6c5d11`; `27e4e4b0-895f-4b7e-a5f2-2d27f914fb2b` | First documentation check failed a Markdown link whose existing target was outside declared link inputs. Narrow correction uses a literal owned-source reference. Corrected documentation passed freshly, 9.429 seconds, at `2026-10-04T04:38:19Z`; exit-zero readback `04:38:54Z`. This is an ordinary documentation predicate failure, with no guard-hook denial or execution-graph change. |
| Final source/metadata coherent suite | `7c60e2cb-2653-4c89-9ffd-a486788fdf14` | All 58 targets passed, three fresh and 55 matching-input cache results, zero skipped/failing; 107 selected targets. Completed `2026-10-04T05:04:52Z`, 121.825 seconds. Nine reported actions; process counters five internal, one Linux-sandbox and six processwrapper-sandbox, with 680 action-cache hits. Counters are not a disjoint action partition. Includes the final exact four-link restoration classifier and reconciled current Codex compilation/source metadata. Later tracker/checkpoint-only edits require focused documentation checks. |
| Final source/metadata coherent build | `30af6920-8c06-44b1-a757-9bd094044a48` | All 107 targets passed at `2026-10-04T05:05:41Z`, 13.699 seconds. One internal action and 348 matching-input cache hits; no fresh compiler actions. The preceding full suite built the changed tooling/source archive. macOS-constrained targets remain skipped. No installed, worker or live promotion. |

Every invocation uses locked Nix tools through Bazel/Bazelisk. The runtime
proof root is `/srv/fast-local/jess/state/codex/omux-bazel9-native-proof-20261003`.
Omux pins Bazel 9.0.1 and Zig 0.17.0. Minimal inherited environments exclude
provider and DNS credentials. Raw environments and private logs are not evidence.
The earlier 57-target runtime suite and 104-target build belong to their stated
source epochs. The current 58-target/107-target gates include the later C++,
Arocc and restoration-tool changes; they do not retroactively change prior inputs.
The user supplied the current lab doctrine during this push. Root read the full
R-C227 board and ruling carriers; [the durable session note](../agent-notes/2026-10-04-sess-omux-evening-checkpoint.md)
records their scope. Subsequent mutations cite R-N13, and future Linear facts
use dated comments with descriptions retained. A Bazel cache-integrity warning
or data-validation failure does not by itself establish a guard-hook refusal;
an actual guard-hook refusal still requires the R-N12 stop and operator answer.

## Implemented changes and proof limits

Import admission and completion now carry exact durable job generation and
process-local source authorization authority. Source detach/disconnect/reconnect
fences matching pending imports. A newer forget revokes an older pending
re-enrollment privilege. Current source and credential deadlines are checked
before domain or ciphertext changes. Synthetic held completions exercise this
boundary without provider calls; no production identity-verification claim
comes from their generated responses.

Request authority reserves a 4 MiB serialized partition; mutation authority
reserves 6 MiB. Admission accounts for escaped byte fields, initialized metadata,
numeric widths and future acknowledgment/result growth before route or external
effects. Immutable completed mutation results release unused byte reservation
while retaining operation IDs and replay. Count bounds remain 4,096 lifetime
IDs with no retirement; byte saturation may refuse earlier. Redacted health
distinguishes ID count, reserved/remaining bytes and conservative guaranteed
mutation admissions. These partitions bound authority sections only; the other
6 MiB is not a proven complete-snapshot reservation or long-lived usability gate.

Those are the saved evening source predicates. The later
[admission sprint](../plans/omux-native-admission-sprint-2026-10-04.md) implements
the shared envelope foundation with its own current-source gates; this earlier
receipt neither proves nor rejects those later changes.

Codex native control rejects conflicting result/error envelopes and same-ID
server requests. Private Unix WebSocket fixtures preserve notification and
unrelated reply interleaving. Stock Codex still lacks the hook; pinned candidate
proof is separate from ordinary launch, resume, same-process provider handoff
and preserved opaque native context.

Installer service destinations cannot overlap payload files, ancestor paths,
ownership records or active locks. Refusal precedes custody-directory writes.
Native clients require an actual selected supported source and derive its
provider. Enrollment requires connected state; manual reconciliation also permits
an authorized detached source. Rebuilt Qt passed the package offline self-check
and the full local suite; Swift source was reviewed but remains uncompiled.
The client does not infer source authorization or expiry. Native GitHub source authorization needs
an explicit absolute path; no client reads secrets. Browser/OAuth acquisition
is not enabled by these controls.

Diagnostic reliability schema v2 distinguishes missing timing, finite bounds
and >60-second overflow; only timed good/bad opportunities contribute histogram
samples. Observations remain in memory, with no independent uptime denominator,
durable scheduled coverage, achieved SLO or contractual/staffed SLA.

Control workers yield partial frames and complete replies while retaining
connection/reader authority. The daemon gate proved fifth-client progress with
four persistent controls, partial/coalesced frame retention and absolute expiry.
The actor independently schedules maintenance on a 100 ms awake-clock interval
checked between invocations. A 16-frame workload held its queue nonempty while
expired encrypted custody was pruned. There is no preemption of an executing
request or maintenance cycle and no 100 ms latency/SLO guarantee. Shutdown stops
new maintenance and drains owned invocation references. A socket reply blocked
by a nonreading peer retains its existing deadline.

Independent source reviews found no additional lifecycle, control-reader or
authority byte-reservation blocker. These reviews do not add allocation-fault,
installed-platform or live-provider evidence beyond the passing predicates above.

## PZM and external gates

PZM is reachable as Darwin arm64 with Nix and existing SSH trust. In the observed
SSH context, the inspected GF cell/worker plists exist but are unloaded and fixed
credential/operator inputs are absent. This does not establish global lane
absence. The user directed further public source exploration on Neo in lab,
Blahaj and GloriousFlywheel repositories. Exact closure transfer and runtime
routing observations have their own receipts; no REAPI build result is claimed
here. Initial Neo discovery rejected a valid immutable `nix-daemon` alias; the
tool was corrected. Default signature policy then rejected the unsigned Neo
outputs. Coordinator materialization `432f3e70-a858-4771-83d8-1c027d26a6b6`
passed using only a per-copy exception for the fixed closure over authenticated
SSH, with Nix store/NAR validation retained and no global trust changes. It
matched all three fixed metadata hashes, 126 declared members and 128 recursive
registrations, totaling 3,151,018,144 NAR bytes. Initial registration identity
SHA256 was `db1032db9e0118bf708d6a37214eceb242829efec89a8382c072756941546f8f`.
This first receipt does not establish stronger exact member/NAR reconciliation
or signature provenance. The coordinator portion of
`26a1451c-fbf8-4521-96da-83ac0edb8c10` subsequently verified exactly the 126
fixed registration records plus the closure root and metadata-closure path;
NAR hashes, sizes and reference edges matched the fixed registration input.
Physical NAR hashes for the two additional paths were recomputed through
declared Nix. The reference-sensitive registration identity is
`d7461660b5fc1c5639dd96e0aaa096ea8ad88499846cb32c87a0a5a5593cbd89`.
This digest uses a stronger identity format than the initial `db1032...` receipt.
The overall guarded PZM transfer failed a declared store operation, and its
complete root remains unobserved; coordinator reconciliation is not worker proof.
Default-policy PZM copy separately failed signature/trust
under `239abf7a-e8cc-4ed2-947e-fcd5136a313b`; complete PZM materialization remains
pending. Read-only Nix transport probes also failed before trust metadata could
be established. Fixed-presence observation
`dd4e91cf-52a1-4dfa-ad81-5d3f9ee2f8d3` found the Determinate Nix daemon and socket,
with no fixed GF jobs/listeners/credential files observed in that SSH context.
This narrows the transport investigation; it does not prove global lane absence.
After the bounded SSH process-exit correction, PZM protocol probe
`b5c21e56-8e94-41a8-bfdf-e0b0c7eec6f0` still failed before trust metadata.
Neo baseline `6b4fb6f5-85e7-4bd0-b0df-73d187c59a7d` succeeded with the same
SSH-ng protocol and immutable remote Nix version; version mismatch alone is not
the observed cause. PZM local `store info --json --store daemon`
`652c5208-08a5-4cac-9a16-82d9f9167f05` exited zero without a JSON trust record,
so its framing predicate failed rather than proving daemon failure or trust.
Coordinator control `8931ce6c-dae7-402e-a074-942378a599fb` returned the expected
JSON. Fixed-presence `b3bb3448-f233-4a48-a6d9-67ff4653c824` observed
`NIX_GET_COMPLETIONS` unset; no environment mutation follows from that hypothesis.
Further PZM calls are held pending a concrete operator context after the directed
public Neo lab, Blahaj and GloriousFlywheel source exploration. No copy retry,
service activation, global trust change or private credential search occurred.

The user subsequently clarified that GF's fable seat on Neo,
`gf-core-adoption-orchestration`, owns the TIN-2998/GF#1717 coordinator context;
the worker is deliberately held with `startServices=false`. The reported
activation prerequisites are a dedicated 4 GiB APFS quota volume, mTLS/JWKS
files, a shared operation lock and 168-hour burn-in evidence. Separately, the
Nix SSH-ng builder's 8 GiB capacity gate is closed with 2.2 GiB reported free;
GC is running under R-C256. That builder is not the REAPI worker. The Q-A
substrate question remains open under R-C244a. These are attributed operator
facts supplied by the user, not new independent host observations. They resolve
the operator-context question without authorizing Omux to start GF services,
signal sessions or intervene in GC. All further host actions remain held.

Provenance helper fixtures passed their recorded narrow gates. Independent
review led to bounded streaming/process-group cleanup in the route probe and
complete regular-input/digest reconciliation in the provenance helper. Actual
Darwin graph loading first failed under
`630a98e1-5fc3-4eec-9ad1-31dc977a020a` while shared BUILD inputs changed.
The frozen retry `f1213e07-e0b8-45ef-9cc0-2748b64393cf` passed analysis of
294,964 configured targets and emitted 58,166,894 private JSON bytes, with no
compiler actions executed. Reviewing that graph identified auxiliary actions
outside archive reachability and an undeclared coordinator-selected shell in
Zig version validation. The helper now follows the explicit archive's producer
dependencies, collapses only identical action registrations with separate counts,
and rejects conflicting reachable producers. The Zig version action uses explicit
declared execution-closure Bash and closure inputs; canonical main-repository
labels passed local toolchain/helper gate
`402cde03-f521-4a0d-baa7-1b3dc4c89b3c`. Post-patch analysis
`78c44f9f-79eb-4be3-b52b-4d1ad1d9f0d1` failed its fixed 600-second repository
inventory timeout with an empty graph and no dispatched actions. The bounded
allowance was increased to 1800 seconds; focused inventory gate
`da4c2c1f-74ef-4cbc-af7b-2dd098fdb3b1` passed. Replacement analysis
`972a3df8-9395-4a98-870c-dd7ba4052763` passed in 609.620 seconds, configuring
294,970 targets and emitting 60,405,120 private JSON bytes with zero actions and
processes. Its fail-closed validator
`2e9ce9cd-3d9e-4752-9892-72f5b81f3c87` rejected an absolute-input closure
predicate in `ZigBuildExe`. More specific diagnostic
`31b9667c-7fa2-4208-ad45-4936d26b2d74` identified an authorized root missing
from the helper's input mapping. Manifest-bound package aliases were added only
for actual declared per-action files, with exact executable/path correspondence;
29 cases passed `1dc3c1c7-4d1a-4a9a-b89a-aefb84b7705f` and independent review
found no relaxation. Run `4a7f3ef7-9b42-4449-9b97-1db62f046532` then rejected
an unspecified schema condition; sanitized diagnostic
`023c4580-bfcd-41b6-8ddd-788e39c5d6a1` identified omitted empty aquery environment
values. Analysis-only proto3 default decoding was corrected while receipt pairs
remain strict; all 31 cases passed `d513e87c-411a-44ec-8393-dddbd8c1dcca`.
Final same-capture run `4332c70d-0952-4a7a-bee4-027c80f57f92` still rejects an
absolute reference outside the authorized closure. That epoch has no accepted
graph summary, complete actual-input provenance or worker proof. The captured graph
SHA256 is `2ab661030f5cbf0f14b3c11a0ab5873882b24002a98b8e6b8238d1323fe3d032`,
measured separately by fingerprint-only run
`fa118b8f-6e32-4d74-b097-f84b07108291`; this is its own analysis source epoch.
The helper's earlier 27 adversarial cases and documentation passed
`8f96c2c0-d8f7-49d8-9440-4456a38fd11c`, including the semantic correction that
receipt properties match the submitted platform rather than proving selected
worker routing. [ADR-007](../decisions/007-local-declared-execution.md) records the
pinned Bazel semantics and independent selected-worker requirement. Analysis,
passing fixtures, input fingerprints and submitted platform properties never
establish actual remote execution or installed behavior.

Read-only diagnostic `7338eaa9-5224-4a38-9ae7-8c6ddcf032f9` identified the
remaining rejected reference as a product `CppCompile` executable-search PATH.
The locked Nixpkgs Bazel default points at coordinator utilities. The selected
C/C++ toolchain now overrides PATH with only its manifest's already declared
coreutils directory. Initial smoke analysis failures
`8e4176bd-3477-4b05-912f-7293d23f016e` (empty C++ environment value),
`f951ee14-56e3-4a44-a15e-842961d7fd70` (private strip API parameters) and
`e9deef33-99e6-4c1c-9f3b-eb1011a2b49f` (PIC-only archive output) dispatched
no compiler actions. Corrected adversarial-default smoke
`fcb9b12b-dc6f-4cdd-ae5f-2a76883bdd0d` passed five fresh Linux sandbox actions
in 16.021 seconds: C/C++ compile, executable link, PIC static archive and strip.
It inspected ten configured action environments; assembly, linkstamp and shared
library environment coverage is analysis-only.

Capture `baaa4c50-7b90-441d-b030-e46c6d335acd` queried the archive's own actions,
omitting dependency producers. Its 48,115,460 bytes have SHA256
`97d536d146ca2d7188b73e1c4ac9b1c2c00958a3823d1c05d05d6a981fdcd209`.
Validator `032f2abd-7b7a-44a8-96d2-055ad901d2be` rejected the incomplete product
plan; diagnostic `aaafc86c-0574-445e-b075-5b10da3f79ae` confirmed that scope.
Complete dependency capture `51c532e0-83fa-4e60-9ac6-7023de3c15a3` then passed
analysis in 445.917 seconds, with 294,970 configured targets and zero processes.
Its 60,402,573 bytes have SHA256
`30ffd8535f33c29ea632e3e55dbc7e8b8981750064dec147f1cb2f6a93303300`.
Unchanged validator `8272d592-6175-41aa-a88b-4c17ece7f508` rejected another
outside-closure reference. Sanitized diagnostics
`2f327dfd-4119-4e69-996d-1f6a9474cd44` and
`99b2e4e1-35d4-4b1c-8e46-bfa81f388fa0` bound it to the owned Arocc `RunBinary`
definition generator's inherited PATH. Pinned Skylib copies the default shell
environment; the in-process generator performs no executable search. Its owned
overlay now sets PATH empty. Actual Linux generator smoke
`4a269a44-f8f7-4571-a3b6-4e3830f44de9` passed in 118.439 seconds despite an
unusable default PATH, with three fresh sandbox actions: SDK validation,
generator compilation and one definition generation.

The final complete dependency capture `22e4eb26-c3e7-4219-909b-a535eae467cd`
passed in 703.648 seconds with 294,970 configured targets and zero processes or
dispatched actions. Read-only metadata receipt
`abbbdf18-e648-48e8-8b8e-c24441961774` measured 60,385,833 private JSON bytes;
capture/stderr last-write time was `2026-10-04T04:21:29.870539+00:00`, with
completion readback at `04:22:13Z`. Unchanged strict validator
`3ebf9dcc-e8cb-4c22-9c28-0b6d70e971c2` exited zero, observed at `04:29:14Z`.
It accepted the archive producer dependency scope: 132 registered actions,
95 unique reachable actions, 99 reachable registrations, four duplicates and
33 unrequested registrations; 31 reachable spawns (nine product and 22 external)
and 64 non-spawns. All required SwiftUI, bundle, archive, CLI and daemon producers
are present. No absolute-input matcher or authorized-root list was relaxed.
The graph SHA256 is
`d4e5299b62ece68797f7dfab9257647501080ce75dc8ab6a937af313f9b12275`, plan SHA256
`15bc1997135a7b0dc4f1c5b1243b31698f2aae9b3951ecb4dff82ddc9573dbc4` and
declared-input plan SHA256
`6acfbcc96fa980fd2830cc506ff4092ffb33c662b78c3625e1e2b7d434658f90`.
This is `analysis_only`: routing, receipt platform-property matching, worker,
bootstrap, artifact and installed-proof flags remain false. No execution log
was supplied; regular-input content/digest reconciliation, fresh remote actions
and remote-cache acceptance remain unrun. The [durable graph note](../agent-notes/2026-10-04-sess-omux-evening-graph.md)
records exact selected-source metadata, fixed manifest hashes, diagnostic failures
and user-attributed operational holds under R-N13.

Neo is the teletype/read-only input source. The matched Darwin closure is
`9k958iwyvk7cn5f7axdfg8a0j1s0nsa1-omux-bazel-closure`, SDK 14.4. Complete
coordinator registration and exact NAR/reference reconciliation cover 128 recursive
paths. PZM registration, independent selected-worker/operator-route binding and
actual remote action provenance are still required. The interrupted old Neo workspace and
unidentified old Sting workspace retain unknown custody; no broad cleanup.

Production macOS custody uses the default Keychain. Private C-driver proof does
not authorize or establish installed daemon custody. Relocated app ZIP, no-vault
CLI commands, interactive SwiftUI, launchd/service behavior, production custody,
Apple trust/signing and development TAR installation remain separate predicates.
No personal vault, provider evaluation, service activation or publication occurred.

## Second review wave

Further source review found three concrete correction scopes: a borrowed source
label surviving replacement during native-file reattachment; terminal enrollment
jobs overwritten by cancellation; and stale encrypted native-setup generations
checked after removal writes. Source corrections are implemented. The new real
file-reappearance and completed-job cancellation predicates passed in the failed
second-wave batch; setup assertions also passed but their fixture leaked an arena
node. After fixture corrections, the seven-target retest and full local suite
passed. Codex removal now guards all recorded bindings before any native detach,
and no longer blanket-releases unobserved routes. Actual private Unix RPC
regressions prove safe refusal for partially observed or empty loaded-thread lists,
while retaining configuration, capability generation and unaffected lease custody. The guard
does not establish durable endpoint/process ownership, duplicate thread IDs
across processes or attachment before the first broker request.

The pinned Codex candidate now installs terminal-abandonment ownership before
checking a structurally valid acquired lease's expiry. Formatter
`bfe5bfc5-1352-4fd9-b470-d34f0a2bafbb` and focused upstream core tests
`ce230cfb-6e1d-43f3-af5b-b3cccdfd3639` passed all 17 broker predicates,
zero failed/ignored (2,594 other tests filtered). Test itself took 0.47 seconds;
the compiled gate took 1,858.068 seconds with both sandboxed and official local
actions. Candidate producer `0d1f1c9f-6d5a-4b9b-a658-4f65681206de` retained
107 reviewed files and immutable base/overlay inputs; new patch SHA256 is
`4a236da5663485458744375f8844898682d4b9f160fd37c00e912fd7cd2e76c3`.
Artifact/tooling oracle `4cad1391-3a88-4b86-9456-f2a774adf0a3` passed two
fresh targets. Final oracle `c8fdc62e-a79e-4301-8303-8ad417ee84cb` passed
current validation-metadata consistency against the actual candidate manifest;
old broad compile/protocol receipts remain historical, with no inherited live
or stock-support claim. Rebuilt Qt passed the package offline self-check under
the second-wave archive gate; Swift remains uncompiled.

Aggregate snapshot review found durable fences commit before external mutation
effects and before returning native leases. A later whole-snapshot size refusal
can still leave a changed native configuration with an indeterminate operation;
that is a concrete availability limit. No whole-state admission reservation or
unbounded lifetime usability is claimed from the authority partitions.

A later domain review found future quota windows could appear as available
aggregate capacity before their start, although routing refused them. The narrow
correction applies the same start/end freshness rule to aggregate admission,
deduplication and shared-bucket minima. Its boundary regression uses two accounts
sharing one future bucket and checks both selection and public-capacity JSON
before and at the window start. The direct domain gate and final coherent suite
passed; the earlier `524a33ee...` suite retains its preceding source epoch.
Verified provider plan metadata also remains a separate follow-up: an existing
identity currently retains its original account type after a later verified plan
change. This is a displayed metadata limit, not a demonstrated routing privilege.

The [Linear receipt](../tracker-updates/native-evening-push-2026-10-03.md) records
NE5 and unchanged issue boundaries. Prior evening write arguments that were not
recovered remain unavailable; authoritative readbacks are retained instead of
inventing historical receipts. The new plan and ledger are now present, following
the earlier tracker observations that recorded their absence.

## Final reconciliation and preservation

R-N13: four dated comments were created and fully read back at `05:13:01Z`:
NE5 `876c2e3c-9c30-4dda-a474-10d9dc025f12`, TIN-5340
`4672837c-29e5-4542-ad7a-3df2961603af`, TIN-2723
`5c21e286-a220-46de-ba74-561fcac47af6`, TIN-1798
`08453e09-dc9c-407d-b1df-ee0c65f85de7`. Bodies matched byte-for-byte;
project and six milestones were unchanged. Issues changed only automatic
`updatedAt` and remain In Progress. Earlier descriptions and receipts remain.

Aggregate documentation invocation `4e8a7402-1162-4798-9e98-acb795f8504d`
passed both targets in 9.735 Bazel seconds, one fresh/one matching-input cache.
All code and worker-owned files are frozen. Final archive/documentation action
`dbdfb5ec-9514-4456-8a2c-636219398356` and source-preservation action
`7e20aafb-62f2-4ce9-b070-ef72689203f3` have their actual results in the
exclusive private receipt named by the ledger. Those planned UUIDs alone do not
prove completion. This external receipt avoids an archive self-hash cycle.
The checkpoint remains partial for Darwin worker/installed and live-native
acceptance, with whole-snapshot admission leading the next local plan.
