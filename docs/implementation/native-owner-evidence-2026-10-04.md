# Native owner sprint evidence

Status: implementation in progress; partial current-source receipts are recorded
below. The complete checkpoint remains unproved. Authority is the [sprint plan](../plans/omux-native-owner-sprint-2026-10-04.md)
and [ledger](../../.goal/omux-native-owner-2026-10-04.json).

The user selected native protocol proof plus isolated installed Linux proof.
The previous admission archive H3, checkpoint c73368fb, 66-test suite and Sting
artifact remain a separate passed epoch. No new owner implementation inherits
those receipts. Stock Codex native support and live provider continuity remain
unavailable. Darwin owner admission and PZM GF REAPI remain held.

R-N13: root owns execution and evidence reconciliation. Twelve workstreams
reviewed actual authority, source/protocol, lifecycle, OS, security and tracker
boundaries before implementation release. FileAuthority v2, lossless generation
wire fields and credential-aware owner carrier are acceptance decisions, not
passing tests. Legacy metadata refuses migration rather than being re-signed.

## First focused component epoch

Invocation `cf80bcba-4f10-4f1e-8b72-edeb1d87c1e5` ran six declared targets
through the locked minimal-environment Nix+Bazel command, jobs 4, keep-going.
Finished `2026-10-04T08:55:44Z`; elapsed 84.567 seconds. All six executed fresh:
five passed, one failed, zero skipped. Reported counters: 45 actions, 91 matching
action-cache hits, 26 internal, 13 linux-sandbox and 12 processwrapper-sandbox
processes; these process counters are not a disjoint target partition.

Passed: recovery, storage, native peer Zig, native peer C bridge and pristine
source-subset exporter. Actual owned C processes exercised bidirectional packet
proof, forked/delegated writers, mixed stream writer boundaries, rights/truncation
descriptor cleanup and retained original process handles. This proves the stated
local profile predicates, not Darwin, installed support or live continuity.

The new owner-storage target passed 35 of 36 predicates. Its real reservation /
SQL commit crash case failed an exact database-byte comparison at SQLite header
change counters after a valid child reopen. The other new substitution, exact
metadata/revision, DELETE-mode refusal and legacy-byte-preservation cases passed.
The crash comparison and legitimate-open boundary require correction and a fresh
run; NO-CRASH is not passed. The failed log remains in the durable Bazel testlog
tree. Independent source review is not substituted for execution.

## Separate Codex source staging

The focused correction invocation `f882ab8d-dc59-489e-84e3-e3aeea98408b`
finished `2026-10-04T09:00:43Z`, elapsed 21.439 seconds. Storage and the new
owner-storage target passed fresh; the actual child crash now publishes its
post-valid-open baseline before reservation and proves exact subsequent refusal
without masking headers. Existing schema3 opens no longer rewrite user_version.
Docs guard passed from matching cache; docs_check failed because the new peer
note's valid tools/native.h link was absent from declared test data. This was an
input-closure failure, not a guard-hook refusal; the declared data was corrected.

Invocation `47f04156-3d9e-42f3-a4e2-e386a43f8778` finished
`2026-10-04T09:02:39Z`, elapsed 32.700 seconds. Six targets passed fresh, zero
failed/skipped: owner ledger, owner request, domain, original request authority,
snapshot admission and docs_check. The recorded logs establish exactly eight
new owner tests and four new request ledger tests at their captured inputs.
The ninth historical-retirement regression and later actual actor tests were
added during/after that action epoch; they remain unrun. This component pass
cannot be represented as a final frozen-workspace or native actor proof.

The original candidate/source remain unchanged. A new private development tree
was fetched, verified, prepared and verified before the two Rust writers were
released. Invocations: `b1bd956f-3476-407d-8f4b-6dd7b6dbaf66` (fetch),
`c483d2b1-b3c4-4400-9304-d9f2b5885b5e` (verify),
`7b6514fb-4714-497b-a24d-cd3579730202` (prepare),
`fae07b14-502e-4df6-b8f0-10dc06603792` (verify-prepared); each exited zero.
The prepared development baseline has 8,515 regular tracked members, 84,372,839
bytes and inventory SHA256
`d1516b7ca018277407de37b1af8463ae002e67cab7ac6664ecdbfe6fef9034a3`.
Official commit is `00c972ed5d6ff6499317fd41b7f23605b8e6850d`, original patch
SHA256 `4a236da5663485458744375f8844898682d4b9f160fd37c00e912fd7cd2e76c3`.
Subsequent development edits invalidate that prepared baseline for final proof;
the new candidate needs independent artifact, inventory, schema and build receipts.

## Native actor and compiler feedback

Invocation `57d09a99-0422-4614-9e60-1d4452315866` finished
`2026-10-04T09:12:51Z`, elapsed 19.966 seconds, overall failure. Owner ledger
and docs passed; the owner run captured nine new predicates before the later
compound-incarnation predicate. Root requested nonexistent integration_setup_test
instead of setup_test. The owner-setup build also caught a local name shadowing
the peer module; that source was corrected. These are ordinary build diagnostics,
not a guard-hook refusal, and do not establish actor proof.

Codex C-action analysis `623df3fb-9ecd-4366-8b8a-0954c60e4f30` failed
because the candidate platform inherited a private root platform. Replacing
that parent with the host platform and explicitly retaining GNU 2.28 plus the
pinned Linux 6.17.13 header profile corrected visibility. Analysis
`57117d18-e88c-4797-a5fa-797462cdfe11` passed in 18.617 seconds, zero executed
actions. Independent inspection established the configured bridge action's
LLVM 22.1.8 compiler, declared GNU/kernel header inputs, nostdlibinc and empty
sysroot; this is action analysis, not compilation or a runtime-kernel claim.

C compilation `980d222c-d5e8-40c2-8d9d-d6b0daaa4466` failed in 16.609
seconds at a libc/kernel struct f_owner_ex name collision. The daemon component
run `d4a7e6fb-5030-4d4b-955e-f7240d7d7c0f` also caught that collision with
its declared glibc 2.42 headers: one admission target passed fresh, eight actor
targets failed to build, elapsed 15.642 seconds. The compatibility fix and both
toolchains require fresh execution. No actor, Rust or installed proof follows
from these failed builds.

## Actor and whole-graph feedback

Invocation `e544b3ec-17bd-47a1-aef4-f09d3147b04e` finished
`2026-10-04T09:52:29Z`, elapsed 65.703 seconds. It requested 13 targets:
the current ten-predicate owner ledger passed fresh, matching peer/profile
targets passed from cache, seven actor targets failed compilation and two
setup targets failed assertions. Invocation
`392eae1d-829d-40fc-9172-4f4b3f43f59e` finished
`2026-10-04T10:00:47Z`, elapsed 80.999 seconds: daemon, setup and native owner
setup passed fresh; six actor builds exposed JSON/loop type errors. Compiler
diagnostics and fixture assertions were corrected without relaxing custody.

Whole-suite invocation `cb6a0d89-bd0e-414d-ac7c-4eabac1d702c` finished
`2026-10-04T10:13:10Z`, elapsed 563.965 seconds, critical path 323.75 seconds.
Of 75 test targets, 66 passed and nine failed, zero skipped; 23 executed fresh
and 52 used matching cache. The graph had 126 requested labels. Reported
counters were 133 processes, 712 matching action-cache hits, 56 internal,
54 linux-sandbox and 46 processwrapper-sandbox; these are not a target
partition. The strict native probe passed all current malformed-channel and
capability predicates. Snapshot migration passed its 209 predicates. Owner
request case six crashed without a useful trace; that crash remains unproved
until a fresh corrected actor run, irrespective of source review.

Failure corrections retain the failed epoch: owned short real fixture roots
respect the production socket-length and directory identity checks; actor
removal assertions expect NativeRemovalPending while lower-level setup keeps
NativeCustodyPending; removed installation registries retain their transaction
and capability fingerprint; installed SQLite inspection handles close before
daemon restart. No production busy timeout, path bound or authority check was
weakened. Docs data now includes the actual delivery/tools public source groups.

Retry `afa46291-1b73-40d0-8f83-78e71e54ad8b` finished
`2026-10-04T10:33:27Z`, elapsed 336.046 seconds, critical path 314.89 seconds.
Three targets passed fresh: docs (0.2 seconds), installed custody (12.5 seconds)
and snapshot import (294.5 seconds). Six actor targets failed to build because
the new static diagnostic variable shadowed Fixture.failure; the variable was
renamed. The import timeout covered the entire target, rather than case nine
individually. A source review found no concrete wait cycle. The measured pass
supports a larger declared test timeout for this expensive target; it neither
measures a production SLO nor changes runtime deadlines. Counters: 19 processes,
188 matching action-cache hits, 12 internal, four linux-sandbox and six
processwrapper-sandbox. Exact-source Sting proof remains unrun in this epoch.

## Separate owner producer compilation and focused Rust proof

Initial eleven-label compilation `2b3d1df2-f46e-4c80-a26a-589d85e128be`
failed after 750.203 seconds. The corrected candidate keeps distinct strict
announce/register response types, converts AbsolutePathBuf explicitly, and
drains the actual MessageProcessor-owned TurnCostWorker through its existing
shutdown-and-wait API. The owner Linux target platform selects the declared
GNU/kernel header inputs; a constrained local test toolchain does not assert
that the execution host runs the header version.

Compilation `c2f210cc-a655-4f3e-8003-f375d168034e` passed all eleven labels
in 538.103 seconds, critical path 475.55 seconds: eight required production
labels and the core, app-server and protocol unit-test binaries. Stable and
experimental PublicSchema actions ran. Reported counters: 81 processes, 7,812
matching action-cache hits, 15 internal, 64 linux-sandbox and two local. This
pre-import compilation cannot certify the later exported fixture bytes.

Focused broker invocation `68d3977f-1f2b-4a5e-b9b0-df1a795664cb` passed
20 Rust tests, zero ignored/failed, 2,597 filtered out; Rust elapsed 0.78 seconds,
Bazel elapsed 7.000 seconds. Focused native invocation
`1b2c5498-310c-458a-87ef-b1c4a69e28d5` took 17.146 seconds: core passed two
actual transport tests and one constructor/pending-ACK work barrier test.
The protocol filter executed zero tests and establishes no behavioral proof.
The embedded app-server gate failed all three configured attempts before
broker accept. Its owned TempDir parent lacked explicit 0700 custody; the
fixture now secures that parent and surfaces early announcement refusal.
Production permission checks and its original three-second bound are unchanged.
Fresh execution of that gate and the strict packet parser remains required.

Official pinned formatter invocations `aa1c6c5b-55c2-4cc9-a03b-ab6216ff38e7`,
`6770a43a-c4e4-44dc-b4bb-f162e7540cc5` and
`9d5b4469-7586-4a1a-af35-ebf6261c2287` passed their stated changed-file
format operations. A complete final check is still pending. Stable rustfmt
reports the upstream nightly-only imports_granularity setting; no toolchain
or warning-policy change was made. All execution used the locked minimal Nix
environment and declared Bazel graph. Rust test process summaries include
local runners; the --strategy=sandboxed flag does not turn them into a fully
sandboxed or installed/native continuity proof.

Actor/tooling correction `d66ee9a3-5f0f-4e36-83fb-15b50c5a526e` finished
`2026-10-04T10:49:18Z`, elapsed 409.882 seconds, critical path 324.24 seconds.
All eight targets executed fresh and passed, zero skipped/failed: native owner
request (55.8s; all seven new actor/ledger predicates plus imported cases),
native owner removal (57.2s; all four new removal predicates plus imported cases),
native snapshot (118.6s), adapter snapshot (299.2s), engine acceptance (62.6s),
unit tests (68.4s), schema import adversarial tooling (0.3s) and separate candidate
artifact tooling (0.2s). The previously crashing request case six passed against
the corrected owned fixture root; this is a new successful epoch, not a rewrite
of its failed log. Counters: 31 processes, 39 matching action-cache hits,
17 internal, six linux-sandbox and 16 processwrapper-sandbox. Adapter saturation
also receives a larger declared test budget after its measured 299.2s pass;
production deadlines and SLO claims are unchanged.

The subsequent embedded Codex gate `9a4422a0-a87d-4a0c-a2c5-121b52765663`
failed all three attempts at its positive owner/register callback, elapsed
77.470s. Actual source tracing established a distinct defect: refusal of pending
native shell work emitted a generic native error, which the app-server marked
as SystemError; its strict idle activation gate then correctly refused. A typed
NativeOwnerPending refusal now preserves native turn/system state, reaches the
client, and is classified only by a private error marker. Real registry/capacity
faults remain generic errors. The strengthened gate checks the typed refusal,
absent shell marker and real ThreadRead Idle status. Its corrected execution
is pending. Two unreachable legacy public-carrier register/unregister handlers
were removed; capability/status and authenticated owner handlers remain.

## Corrected native admission and current graph

Invocation `02da1c06-c41a-47c2-b8cc-23f48204b345` passed three freshly
executed targets, elapsed 516.032s, critical path 500.97s. Core ran three actual
peer/constructor predicates (zero failed or ignored, 2,615 filtered); app-server
ran three predicates (366 filtered), including the real embedded ThreadStart
path with held ACK, typed pending refusal, absent shell marker, actual Idle
state, wrong nonce and a distinct child writer before the positive ACK. The
child helper alone is not independent proof. Protocol ran one exact known-wire
pending-error predicate (354 filtered). Counters: 94 processes, 4,557 matching
action-cache hits, eight internal, 83 linux-sandbox and six local. Private-marker
broker classification and complete schema fixtures require their own gates.

Updated compilation/producer `47b36016-b87d-4c8e-bafa-352eebd63b6c` passed
ten labels, elapsed 534.734s, critical path 520.83s: the eight required production
labels plus config and app-server-protocol test binaries. The stable and
experimental native PublicSchema writers each executed one helper, with 318
filtered tests; elapsed 8.57s and 8.32s respectively. Counters: 61 processes,
2,018 matching action-cache hits, 14 internal and 47 linux-sandbox. This receipt
predates fixture import and does not certify the final packaged tree.

Documentation/formatter/exporter tests `432d5d67-33a1-42d8-9c07-59a6835d1911`
passed three fresh targets in 13.306s. Export
`33790db2-068e-4cfa-a5d4-9e0e43d678a7` obtained 1,147 pinned Git originals,
including original public schemas and the nine additional reviewed source paths;
the bounded archive is 1,759,260 bytes, SHA256
`5b422ac30328fbf2fc660d6440e09aa47e8c8de15f379c3d02ea94fc3a904486`.
The edited development source was not its authority. Read-only graph/C-copy
check `3518de93-f66f-4eb7-8b8f-5a7f27394dd2` passed and found identical
daemon/candidate C bridge bytes and current 13-archive tool profile. Omux format
run `939fd386-247b-4fdd-a1a5-95b30fd0ee0f` built successfully but refused
missing operator arguments; corrected invocation
`5862c598-e673-4906-8310-f1a37af44867` formatted `src tools` successfully.
These failures and corrections remain separate receipts.

Exact import `56dd735d-8a8f-4f0b-8c2c-8b744d8e8524` copied 1,098 native
producer files, 4,432,585 bytes, without normalization or compression. Its
exclusive private receipt binds producer `47b36016`; this count includes
unchanged files and is not the candidate changed-file count. Config generator
`c6980c2d-fc39-4a51-9067-2a2de6a61cb9` passed. Fixture execution
`6a50453b-b843-47c4-905c-85eaf3771a12` passed both requested targets freshly
in 157.135s, critical path 152.49s: app-server-protocol ran 318 passing predicates,
zero failed, one intentionally ignored writer, zero filtered; config ran 342
passing predicates, zero failed/ignored/filtered. All JSON, TypeScript and both
compressed public fixture families passed. The actual core config schema fixture
is a separate core predicate and remains pending at this checkpoint.

Whole graph `31cc04ad-2825-4d3f-95fb-7433b7f3c405` finished
`2026-10-04T11:18:30Z`, elapsed 780.384s, critical path 367.74s. All 77 test
targets passed, zero skipped/failed: 21 executed fresh, 56 accepted matching
cache; 132 requested labels comprised 55 other targets and 77 tests. Counters:
85 processes, 788 matching action-cache hits, 35 internal, 29 linux-sandbox,
42 processwrapper-sandbox; not a partition. Measured snapshot import/adapter
targets took 340.4s/346.2s. The Linux runtime archive was 60,248,573 bytes,
SHA256 `7d80531a35d841f894ec1cb06d50eafa618368be1b4cd3063e0ab2969a083705`,
with 138 artifacts. The separate candidate artifact test remains manual until
real data is staged. This full graph predates candidate packaging and tracker
publication; its source archive is not the final installed-proof source.

## Separate candidate and static consumer

Candidate producer `247e7ef5-8c34-458a-9c79-13e35cb1e6c3` passed, elapsed
18.916s, and packaged 164 reviewed changes against the bounded immutable Git
originals. This preserves the old 107-file artifact without editing its bytes.
Exact schema receipt and validation overlay staging `84c70e9d-df70-4e96-8185-14aa710a34f1`
passed. New artifact identities are:

| Object | SHA256 |
| --- | --- |
| Product patch | `2e5542c5f6a44e3a8dd38b4a4093d1735ff19771721b05fc51f55b475b1a8d46` |
| Original subset archive | `a794a67af4b6aecd9e91aeb4281354b90d10e10134e7cf6a6028b33f26a2f9d9` |
| Binary schema overlay | `9d47862cd9e7e1a911d8512dad0ad0f124c928e139b778cd1e89ecfce17c5703` |
| Exact import receipt | `485672178e95148b88b96b9bc30970636d365a4f74be2d084a41b8d95dc1e12c` |

Broker run `137f883b-c389-4960-b49b-7093a6f557e8` passed 21 actual Rust
predicates, zero failed/ignored, 2,597 filtered, Rust elapsed 0.58s, Bazel elapsed
405.073s, critical path 395.45s. Its additional schema_tests filter matched no
config predicate, so no config-fixture proof is attributed to it. Correct actual
fixture run `15d3f3b6-8a50-4bd8-85e0-a4e77c45b74d` passed
`config::schema::tests::config_schema_matches_fixture`: one predicate,
2,617 filtered, Rust elapsed 0.14s, Bazel elapsed 17.548s. Final official
formatter check `083b81a4-8e25-4133-a344-9bf5af59aafd` passed all 22 changed
Rust paths, elapsed 4.016s; no formatting mutation was needed.

New source verification `9b9c8062-2e2e-4423-8dbb-f3e533c18754` failed
because the historical verifier fixed local_linux-fastbuild convenience targets.
Its correction accepts only an explicit known configuration and preserves exact
owned/canonical link targets. Fresh candidate/restoration/docs gates
`7ae04a04-f71b-4bfe-a632-ac532cc0ae49` passed all three targets in 36.311s.
Complete verification `5a9d8326-5327-4052-8a6e-946dcc4d18ac` passed with
owner-linux-fastbuild: all 8,546 tracked source files, 84,588,390 bytes, complete
inventory SHA256 `3400115fae8ef204f2ce085880b40887bcb14e2080236ba87a34be9b14fe7d3b`,
official tree `6fa1a3767a92ba5d579fcaf724fdce3049c2070b`, unchanged graph
hashes and exactly four generated output links. Receipt is exclusive, private
and retained separately from source. Final compilation remains its own gate.

Runtime reference producer `372bf2fd-35a4-41ac-9a6b-9286d18f7ea3` passed.
Its 16,408-byte JSON has SHA256
`06d4108e4a94ca84e13397a1e8c0c19acd2acc2074aa1ee23bb1d9accffdba15`.
SPA startup `3c16e55f-fc3b-4fa8-90af-df4669d87c45` failed before graph
execution for unavailable Java home in the minimal environment. The locked SPA
flake now sets its own pinned coordinator JAVA_HOME. Retry
`abacbba4-c2c2-46f3-978c-3a3ebd7f97d7` validated the reference digest;
import `4c5d39b6-8066-4cd2-80dd-9e3513d2b0ac` passed with that explicit
digest. SPA `5a169d3f-cc10-48d7-8696-4a1845f0b1cc` finished
`2026-10-04T11:30:59Z`: eight fresh targets passed, zero failed/skipped,
elapsed 129.338s, critical path 104.74s, including production archive and three
declared browser gates. This is static-consumer proof; no publication occurred.

Final-source production `185ffba7-9b08-450f-ab29-1d405810892a` passed all
eight required labels in 369.239s, critical path 364.81s; 31 reported processes,
2,058 matching action-cache hits, five internal and 26 linux-sandbox. Both native
schema writers passed their single helper with 318 filtered predicates, stable
8.59s and experimental 8.66s. Read-only fixed-point check
`31de0ad7-65bf-4dd1-8d25-e424821c4a20` passed: every one of the 1,098
regenerated files equals the exact imported receipt and current source fixture
bytes. No normalization, recompression or second source import occurred.

Fresh final-source native `2e9809d2-3c39-4c4f-bb92-210743421adc` passed all
three targets in 67.324s, critical path 64.78s: core three predicates (2,615
filtered; 2.26s), app-server three (366 filtered; 0.91s), protocol one (354
filtered; 0.00s), zero failed/ignored. Counters: six reported processes, 71
matching action-cache hits, one disk-cache hit, one internal, two linux-sandbox
and five local; not a partition. The helper child alone is still not proof.
Candidate validation reconciliation `73f2de9f-750b-42a2-b2c1-245e3a017a79`
records these actual final-source gates. Native installed interoperation and
ordinary launch/resume/provider handoff remain unperformed; stock support false.

## Remaining reconciliation and next work

At this pre-host checkpoint the selected Linux owner predicates had current
local evidence. Exact-source Sting installed custody, the final default graph,
dated tracker publication/readbacks and final source/Git/context remained
required. Their later receipts follow below. This checkpoint cannot promote
seamless continuity.

The next implementation priorities are a real installed Codex/daemon interaction,
verified endpoint advertisement/discovery, and an explicit daemon-replacement
reconciliation protocol for retained uncertain registration/removal operations.
That protocol must obtain original authenticated evidence without retransmitting
uncertain effects or replacing global work keys. Ordinary CLI/TUI launch, resume,
accepted streams and provider-bound quota handoff need dedicated version-bound
live gates. Darwin native owner identity and Apple SDK/runtime proof remain held
until GF's PZM lane supplies its own active authority; no Neo compilation follows.

## Final default graph and frozen installed-proof inputs

Invocation `7f4c37cc-d5fb-4b32-ae02-e0289c5471a3` finished
`2026-10-04T11:41:49Z`: all 78 default test targets passed, zero failed/skipped,
five freshly executed and 73 accepted matching cache; 133 labels comprised
55 other targets and 78 tests. Elapsed 34.054s, critical path 12.56s; counters
26 reported processes, 712 matching action-cache hits, 20 internal, one
linux-sandbox and ten processwrapper-sandbox, not a partition. The candidate
oracle now belongs to the default graph. New artifact bytes, strict source
restoration profile and nine completed local acceptance predicates are coherent.

Private freeze `9540d589-4d5d-4db2-b99f-30b023f8b7ae` passed source,
runtime and reference comparisons but stopped before captures because an
assumed command.log file was absent. It produced no passing receipt. Corrected
freeze `b7638458-6a25-43b8-a034-e02a7fb767f2` completed at
`2026-10-04T11:46:18.355926Z`; it uses the observed retained invocation profiles
and actual current test logs. Every regular public-source member matches the
workspace bytes and normalized executable mode. All copies and receipts are
exclusive, mode0600, fsynced in a private mode0700 owner-frozen directory;
the failed capture receipt is retained separately.

| Frozen object | SHA256 | Bytes / scope |
| --- | --- | --- |
| Prehost/pretracker proof source H1 | `4af51426654a100a7e3c5981506d16ffd336527ffa60ec717cd97003409b2641` | 6,493,385; 317 regular members / 17,659,470 raw source bytes |
| Linux runtime P1 | `7d80531a35d841f894ec1cb06d50eafa618368be1b4cd3063e0ab2969a083705` | 60,248,573; 138 runtime artifacts |
| Generated public reference | `06d4108e4a94ca84e13397a1e8c0c19acd2acc2074aa1ee23bb1d9accffdba15` | 16,408; equals SPA bytes and digest sidecar |

Sting dispatch `f0dca063-53c0-424e-8b89-75d9a7e2c8d2` uses only frozen
H1 through the existing authorized linux-installed recipe. Proof
`c8a06e09-b044-40a5-a15d-c88a28d016fa`, private workspace `.run-o8Shxvqw`,
reached action execution at `2026-10-04T11:48:41Z`. At that observation its
result, runtime-byte comparison and cleanup were pending; phase observations
did not establish PASS. The actual terminal result follows below.

## Actual installed result and Git preservation

The terminal Sting result exited zero and passed the fixed installed target.
Graph and remote exits were both zero; cleanup and current_cleanup_result were
both removed, including the owned `.run-o8Shxvqw` staging directory. Observed
host metadata is Linux x86_64, kernel6.12.0; this is not a blanket native-peer
capability certification. Its complete graph log digest is
`f17c174e002801dedbc3677c7a0c4a39aba43faff4520e0860f8fc612af7301d`.
Root observed the terminal result at `2026-10-04T11:57:08Z`.

Independent comparison `1f4baea4-6d73-4a75-9647-47c2f7d648b2` passed at
`2026-10-04T11:58:58.511147Z`: terminal/progress records name the same proof
and frozen H1 source, H1 hashes match the actual dispatched private copy, and
the remote runtime equals independently captured local P1 bytes and SHA256.
Exact source/runtime values remain those in the table above. Terminal and
comparison receipts are exclusive private fsynced copies. This proves packaged
Omux daemon/CLI/offscreenQt custody with private XDG and a genuine disposable
Secret Service, including bounded restart/custody predicates and owned cleanup.
It does not prove installed Codex/daemon interoperability, interactive desktop,
managed service, personal vault/account, provider or seamless native handoff.

Git preservation `2bdff2d7-2bd0-4f11-920b-90a47c8b6449` passed at
`2026-10-04T11:55:46.666984Z`. Declared locked Git saved private history bundles,
tracked HEAD/index/working diffs, complete status and exact index bytes for both
dirty checkouts. Omux remains codex/omux-native-reset at
`f5f83c1ad99c2920de6759791b327a99a02a2ec5`; SPA remains
feature/native-account-custody-reference at
`72c808b3a8e7614b29d8932aaaf9f97d53912169`. Index SHA256 values are
`5e620bda824bf9b364c854433d7ab2aafd128dd83c0f9ff8262e7fd0ada4e30f`
and `ed101d86c2ee990aeb4b33511489a317b2e06d9ffe2fe29f1d03e7267ae45aeb`;
before/after HEAD, branch and index bytes match. No commit, reset, stash,
checkout, push, service operation, provider access or personal vault occurred.
Untracked working bytes and final context are retained by the separate final
source/tree capture; the tracked diffs alone are not their proof.

## Tracker, complete working trees and final SPA proof

R-N13: four dated comments were created and fully read back at
`2026-10-04T12:04:46Z`. TIN-1798/5336/2723/2050 received respectively
`783c66ad-28ac-4e2c-a8be-5c95374593a6`,
`fa45a9c7-f4f4-4fa6-8fbe-8d577e38364e`,
`002bcd1c-838b-40b0-b433-3bbfdfbc07ba` and
`6ba6542e-ee35-433b-8c56-52b219b1da21`. Exact saved/readback bodies and
every prior comment field agree. Only automatic issue timestamps changed;
states, descriptions, owners and other returned issue fields were preserved.
Full redacted receipts are in the [tracker record](../tracker-updates/native-owner-sprint-2026-10-04.md)
and its JSON. No issue/project/milestone edit or additional comment occurred.
R-C227 and the complete 253-comment coordination inventory were re-read before
publication. OI-SCHED retains PZM database custody; GC and GF activation remain
held. No guard or automatic-review refusal occurred.

Private working-tree capture `a851bc17-1f51-413b-82f9-9ba12f61d706`
passed at `2026-10-04T12:21:53.885466Z`. Omux tree
`2b6484f936626e57a7d6cf0321a76f97ae65ce7a` contains 548 nonignored files,
16,429,210 source bytes; SPA tree `dbdff322f3577bacfc97bc97750a0a2e74fc9247`
contains 119 files, 772,664 source bytes. Each stored blob and independent Git
archive equals its original working bytes and executable/symlink mode. Complete
untracked files, inventories, current diffs/status, exact D1 indexes and history
bundles are retained under the private owner-checkpoint directory. Strict object
checking passed; both original HEADs, branches and index hashes stayed unchanged.
Only private tree references were created; no commits or public references.
Initial operator `577b638b-2a1c-4a40-8a90-629f480ab0c9` stopped on a
Python argument-order SyntaxError before any tree capture. Its script/failure
receipt remain separate; the corrected v2 operator produced the passing receipt.
The retired Zig-build watch paths in `.envrc` now name actual Bazel inputs.

Final SPA scoped check `3b38c9e6-51ed-4a66-9e40-ea39476ad145` passed
five fresh targets, 45.620s/42.77s critical path. Its rendered archive differed
from the preceding browser-proven bytes: comparison
`622a18d4-9b3c-4c35-874a-9257484c02c4` failed; inventory
`d811d439-55f4-4a55-b2d0-6f3392f972f3` found 42 changed members.
Pinned SvelteKit2.59.1 defaults `kit.version.name` to `Date.now().toString()`
in its config options; that timestamp propagates into generated chunks/version
JSON. The SPA now hashes sorted declared rendering inputs, including exact
source/static/script/config/package/lock bytes with path/length framing, and
copies required lock/build/sync inputs into its owned build scratch tree.
The digest excludes nonrendered notes, clock, mtimes, environment, Git and
absolute scratch paths; missing required inputs fail rather than use a clock.

Fresh corrected SPA `5a8c4d83-fb44-45a8-9e7b-8968799dfc05` passed seven
gates and failed Puppeteer navigation in 80.784s/79.23s critical path. That
check awaited a full navigation event during SvelteKit's client-side route
change. It now waits for the actual destination URL and rendered title while
retaining its content, viewport, overflow and exact API assertions and timeout.
No retry or timeout increase hides the failed epoch.

Final `76f2f45e-7438-41a8-bc8d-4e80f89e90d2` passed all eight gates:
six fresh, two matching-output browser cache, zero failed/skipped, elapsed
63.295s/62.10s critical path. Its production build actually reexecuted after
the nonrendering check input changed. Comparison/capture
`1eefcc6f-1b4c-4dda-b7b2-0d335dfc0d1e` passed at
`2026-10-04T12:25:16.722023Z`: both production archives are byte-identical,
SHA256 `65e92fb3dec7f32545df23b99f5e250c27ebfb64ee99a9d7658df8a3c133071e`,
1,006,533 bytes. The generated version is
`27e81bf8e710b1e153ca70671f50625fce733f201a6dec8bab3ebb0b08f0bd8a`.
The exact public reference remains `06d4108e4a94ca84e13397a1e8c0c19acd2acc2074aa1ee23bb1d9accffdba15`.
Final archive, profiles and browser/check logs are exclusive private fsynced
captures. This proves two local builds and the stated browser predicates;
it does not establish universal/cross-host reproducibility or publication.

Independent final custody review found no new runtime blocker or support
overclaim. Final closing context/source receipts remain a separate documentation
epoch from installed H1/P1; runtime and native support claims are unchanged.

## Bounded acceptance closure

R-N13: current documentation check `1a4a58e7-5408-4b6b-9e1a-f3a6ff519c19`
passed freshly, elapsed6.111s/4.12s critical path. Complete working-tree D3
`4d9d4cf0-9d5a-4130-a898-c0ba1eb0ae61` passed at
`2026-10-04T12:28:02.640457Z`: Omux tree
`d37ce695e4ed5a0ce3be946aa75bff49274a5531` contains548 files/16,435,245
source bytes; SPA tree `b6a0718f8eae7612d090564b7fc8c59efce00076`
contains119 files/772,806 source bytes, including the final navigation check.
Receipt SHA256 is `be1683cfd94d8ee23a6d812f4343a1bc2f16799c9e7857dcd5252ade49ea9beb`.
Independent blob/archive byte and mode verification, strict object checks and
original HEAD/branch/index preservation passed for both repositories.

All ten selected acceptance predicates have actual scoped evidence. The ledger
records bounded acceptance passed with no remaining bounded implementation gate.
Closing ledger/plan/note bytes are included in a separately captured final
source/context epoch; no self-hash or installed claim is attached to those later
documentation bytes. H1/P1 remains the actual installed proof tuple. Final
context and scoped documentation checks use the same locked Nix/Bazel discipline.

Installed patched-Codex/daemon interoperation, automatic endpoint discovery,
producer daemon-replacement reconciliation and live ordinary-launch/resume/provider
handoff remain separate next work. Stock `native_support` is false. No upstream
submission, public deployment/release, provider/personal-vault use, managed service
activation, PZM/Neo compilation or host recovery occurred. Reliability objectives
and repository roles were preserved without an achieved SLO, contractual SLA,
staffed support promise or appointed human owner.
