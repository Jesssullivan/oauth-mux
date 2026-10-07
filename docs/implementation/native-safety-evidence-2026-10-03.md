# Native safety sprint evidence

Status: final Linux graph passed on locked Bazel 9.0.1 (54 test targets,
96 build targets, including coordinator tools and the corrected runfile mapper);
Sting installed proof and private Darwin vault IO passed. The observed Darwin
link declaration is corrected, and the known failed workspace is removed.
The combined client, CLI and SDK-stub corrections passed the local graph.
The previous Darwin run's unresolved dependency is identified; all three exact
historical workspace repairs passed. The updated Sting runtime graph and exact
artifact passed, but its composite recipe failed the fixed 20-second cleanup
deadline. Reviewed cleanup and TreeArtifact corrections passed the full local
graph; all four exact known Darwin workspaces are removed. The final bounded
Sting identity lookup found no match, retaining that old scope as unidentified.
The updated Sting runtime composite passed from frozen source `0be0a6...`,
including current-workspace cleanup. The user stopped Neo compilation and
designated PZM's established REAPI lane as compilation authority; Neo is a
teletype/source-inspection host. The interrupted Neo caller exited 130; its
remote result and current-workspace cleanup remain unknown. The
original five-hour checkpoint remains historically partial.
This record does not establish supported native continuity. Scope and checkpoint are in the
[sprint plan](../plans/omux-native-safety-sprint-2026-10-03.md).

Source custody: branch `codex/omux-native-reset`, baseline
`f5f83c1ad99c2920de6759791b327a99a02a2ec5`, existing uncommitted reset retained.
Receipts below bind working-tree predicates; no committed or shipped artifact
is inferred. All project invocations use the locked flake's
`nix develop ... --command bazelisk` path.

## PZM REAPI correction and pause checkpoint

The user requested a graceful pause for lunch, with evening resumption. The
[evening handoff](native-safety-evening-handoff-2026-10-03.md) records unfinished
work, source custody, worker disposition and cleanup. The original five-hour
checkpoint remains partial; pausing does not complete outstanding acceptance.

Final source test invocation `402bfcc8-0e1f-4725-9a08-806a69cc8f85` passed
54 targets, zero skipped/failing, at `19:49:51Z`: nine ran fresh and 45 were
accepted from the local action cache. Build invocation
`133a5eb0-8d62-4199-a81b-5896c03486e0` passed all 96 targets at `19:51:17Z`.
Both used locked Nix, disabled home/system rc files and the durable output root
`/srv/fast-local/jess/state/codex/omux-bazel9-native-proof-20261003`.
The first Bazel 9 attempt, `53f793ea-2b3a-4f90-9cd5-d7c27f6a6194`, failed
analysis because the global C++ toolchain configuration provider was removed.
The explicit `rules_cc` provider import corrected it; the preceding 54-test
pass `de075959-7747-41ee-8a1b-0c3f898a71a7` predates the final bootstrap tools.

Current Linux archive verification
`60d57b35-8c2c-4a4e-b791-88665e7875c9` passed at `19:52:10Z`: SHA256
`1c25304f169166ef04c71fc61c471b2c57d59f23a6bbad0b29b9c4976f46728d`,
59,741,056 bytes, 138 artifacts, experimental dirty development provenance.
The final local installed/relocation cases exercised this current archive.
The dedicated Sting `0be0a6...`/`a49ad0...` receipt below remains its separate
historical artifact epoch; it is not a dedicated-host receipt for these new bytes.

Read-only Neo recipe invocation `6ef60b23-b030-4d8e-8c29-6a617f10d6e6`
observed Legalab's Bazel 9.2.0 recipe, `gloriousflywheel-bazel` front door and
remote-only/no-fallback flags. The local lab flake pins that wrapper's public
source at GF `04f9c8587ae9b203e4bedb26f11954bb3f6bdda6`; it consumes operator
executor/cache/instance inputs and a runtime `gf.platform` selector. Source
inspection does not establish an active PZM worker binding. Omux itself now
uses the flake's locked Bazel 9.0.1, not the consumer example's version.

The native repository separates the coordinator's bootstrap Python from the
execution manifest. `@omux_host` exposes the declared host Nix/SSH/Python/Bash
closure; these tools are excluded from the application runtime closure.
The endpoint-free `darwin-reapi` profile selects arm64 macOS, remote actions
and tests, no local fallback and one job. The `reapi-proof` option disables
cache acceptance. Pool mapping, endpoint, instance and auth remain operator inputs.
Focused host-tool repository build `be913f4a-90f9-46e1-a18f-c2a0b49afdc0`
passed at `19:38:08Z`. Actual offline resolution
`98d7e583-d2e9-414c-8f7b-4ab90c97ae39` passed after correcting Bazel 9 runfile
location aliases. Initial resolution `28740d95-88a1-47d5-9f12-d8b3d36226c2`
failed before that correction and remains a failure.

The exact current Darwin closure is
`9k958iwyvk7cn5f7axdfg8a0j1s0nsa1-omux-bazel-closure`, matching Neo's
existing immutable metadata observed by
`07635590-fc14-4fda-871a-6fd54d0fb8b1`. Its native manifest SHA256 is
`fdfeb78902a8fb28d2e7cff6c4516558c9b0b5e9c4b154b2981a49e561b25087`;
system `aarch64-darwin`, SDK 14.4, 126 store paths and 1,018 registration lines.
Store-path metadata SHA256:
`1fb5ca0076bc83a7cc5fb36e73abc4f15a892db8930aa56ff6fc1bbc57e32153`;
registration SHA256:
`4c4d533eb8fa4d87215d292ad9ea8dfd9c2629d1538d51cad0430591f01cb3d3`.
No closure transfer, Linux-side Darwin action analysis or PZM REAPI execution
has occurred. Local fixed-input presence check
`a0c6e539-874b-44c8-bfbf-d2d7b5614ea4` found all five wrapper variables absent
in this process context; it says nothing about other operator contexts.
The reviewed 22-case transport/metadata suite
`149743ea-24e0-4a55-910a-7490d0d71b97` passed, including exited-leader
descendant cleanup. Its earlier immediate child-state fixture assertion failed
under `15fd...`; bounded scheduler polling corrected the fixture.

Three clean, unlocked legacy worktrees were removed with ordinary Git removal,
without force or branch deletion. Their unique commits remain on named branches:
release hardening `fb76a5585401a82f9ce1e834ab62c76ac214d4e2`, redacted route
state `f3bd4d2bc8b3b4034414d91606d322379d2ad8db` and resource cassette
`87d37c3af9512a6f2727d862e6370f08de869100`. Post-removal worktree/ref
readbacks passed. Only rebuildable pytest cache files were discarded.
No public temporary/backup/original files or active native-reference dangling
links were found. Retired references in explicitly historical documents remain
inert evidence. The active runtime and SPA dirty checkouts are preserved.

## Focused source receipts

| Predicate | Target | Invocation | Observed result |
| --- | --- | --- | --- |
| Durable request fence | `//:request_authority_test` | `256818f0-b0d0-496f-8f41-dd79b57f8e18` | Six embedded cases passed, including restored issue ordering, acceptance authority and 64-character request IDs; module proof only. Supersedes the earlier five-case receipt. |
| Allocator-owned bounded mutation fence | `//:mutation_authority_test` | `b9130520-5af8-45fc-ae80-598016ec0f88` | Nine cases passed, including 4096-record saturation, compact serialization below 16 MiB and allocation-failure restoration. Supersedes the earlier seven-case receipt. |
| SQLite recovery authority | `//:storage_test //:recovery_test` | `3c278876-3169-4ab8-9b1d-c1fe0fe07a68` | 24 storage and six recovery cases passed; synthetic keys, no vault/provider IO. |
| Strict runtime and legacy singleton custody | `//:paths_test //clients/linux:runtime_paths_test` | `291c31c6-0ca2-457b-9621-a2449a5863dc` | 12 Zig cases and Qt helper security fixture passed. No Darwin execution. |
| Bounded reliability observation | `//:reliability_test` | `1eaa9914-1e3f-493b-8c1d-76553e270bb7` | Six module cases passed; no installed availability denominator. |

| Genuine isolated Linux vault | `//:vault_realproof //:vault_bridge_test` | `0fff5b21-aa20-4b4f-a474-17dfe8de2fd9` | Real Secret Service binary roundtrip, reopen, immutable create, malformed-key rejection, deletion and ABI cases passed. Disposable D-Bus/keyring; personal vault untouched. |
| Installed Linux custody, exploratory source | `//delivery:installed_custody_test --test_env=HOME` | `8071e309-4c37-4fc7-a2b8-6bc67e49585b` | Production daemon process restart, CLI aliases, lost-reply deduplication, actual Qt socket/state requests, old-SQLite rollback rejection and ownership uninstall passed. Archive SHA256 `7a1b39022661ace74640156a9699e9e0a941be45dfd169b8a3d0e416adaaaa67` (59,741,362 bytes). Predates final capability/poisoned-state changes; superseded by the final installed receipt below. |
| Earlier control-v2 reference and SPA | Producer/import and seven SPA gates plus formatting | `50e379d6-cada-46af-91f7-ec4648d8250d`; `58270c65-8cb6-48bd-972d-5cf1be299f64`; `74464040-10f0-4714-a3e5-6005d107b77d` | Earlier bundle SHA256 `80afb9c1e6f9e8293e03863738bcbe9e82d4246586eca301da0bf83244127fbf`; seven unit/reference/archive/browser gates and formatting passed. Subsequent digest `166cec94-fc4f-460d-9d69-adb7c87efd21` was identical before the final self-documentation correction below. No deployment. |

## Final self-documentation reconciliation

Source summaries now distinguish source disconnection's invalid grant metadata
from deletion of retained ciphertext. `src/control.zig` and `src/reference.zig`
changed only that wording. Source reference test
`03efda99-fb52-430a-8102-e7fe2743fdb0` passed; producer
`3dd00954-3197-4781-8c55-9bd1d6e83be3`, digest
`0cf72059-7053-4526-805b-db9979354a95` and actual SPA import
`17ab8784-28e7-4496-96c2-bd8580828e0d` passed. New bundle SHA256:
`f6467e0f6ebfb0a6ceffeb9be9eccdf006f4d26968caa2a1e1eaf8ae61c44c74`.
The separate SPA's five applicable gates (`unit_tests`, `svelte_check`,
`reference_check`, `archive_check`, `format_check`) passed under
`aec7cc1c-7efb-46cf-bd5d-657f6661534b`. Both repositories used clean inherited
environments retaining actual HOME, the locked flake and private durable Bazel
output roots. No deployment occurred. A first source command requested a
nonexistent `control_test` target (`2343f858-f74e-48ed-b44d-56d3344e8d6f`);
no actions ran, and the corrected declared reference target passed above.

Read-only native-wire review found no material compatibility blocker between
the new fences and Codex's candidate protocol 1, the Git helper, browser protocol
1 or control protocol 2. Candidate UUID request IDs remain stable across the
two-attempt loop. This source review is not a live outcome receipt. The Codex
candidate README now states that unacknowledged terminal cleanup retains
in-flight authority beyond credential expiry; expiry cannot prove work finished.

Subsequent thin-client review found a concrete gap: the daemon can durably mark
an external mutation indeterminate and return its original JSON-RPC error, but
Swift and Qt treated a declared error as settled and permitted another operation
identity. The correction retains the original ID before callbacks, queries
`operation.status`, recovers a completed object result, releases only on an
authoritative `UnknownOperation` response, and retains the fence on started,
indeterminate, malformed or unavailable status. This is same-installation
reconciliation; installation replacement/full-user rollback are outside that
authority. Independent source review approved the final Swift/Qt implementation.
Qt transport/control invocation `5b83174c-a5cb-4e14-af7c-17d0fea46c5e`
passed ten named socket scenarios: four prior cases and six new reconciliation
outcomes, including reentrant action refusal, stable wire identity/revision,
completed recovery, explicit absence and held indeterminate/malformed/query
failures. A preceding client gate `862a474c-f7f0-44f3-ae6f-26f6bd9f0d32`
passed before final local ID validation and UI hold display corrections.

The CLI now emits redacted stderr guidance with the original operation ID on
declared or malformed mutation replies, preserving stdout and performing no
automatic query/replay. Source review approved. Scoped formatting passed under
`a042e37b-1e53-4ece-861e-844b0d4ab186`; actual CLI invocation
`d03e32e2-daaf-4690-8b87-d14a402ee6f9` passed nine cases: three existing
Git cases and six CLI cases. Five mutation fixtures recover the original ID,
then an explicit subsequent process queries that same ID and sees indeterminate
state with one recorded effect and no automatic query/resend. Generated IDs
are 32 hex characters; explicit caller IDs remain unchanged. One-shot CLI
guidance cannot gate independent future processes. New combined graph and final
Linux/macOS artifacts remain required. The `699298...` Darwin archive predates
this client correction.

## Final integrated graph

### Original-deadline cleanup correction and Neo packaging failure

Final Sting installed-custody **composite passed** at `18:34:19Z`:
proof `fb703896-cde8-4cac-a3cb-20cfc5baa6dc`, orchestration
`d889391c-2091-4d76-9ef3-3c8c78f45178`, exact source
`0be0a6ba61854b608b26bdd3706d122eae0bf427528101d2dffb6ca13101f430`,
Linux x86_64 kernel 6.12.0. Graph, remote and local exits are zero; current
`.run-7Vx7V1E1` was removed. The archive is exactly
`a49ad024d06d6864097007e4d1c7c0729e9415c830c2cc1427c92680d3e6aa5a`,
59,741,174 bytes, matching the local corrected runtime/client artifact.
Complete private log SHA256:
`c1f73826db572b6eb65958f9428d1620fd0e50cede062859f209041ad777da9d`.
Graph-complete was observed at `18:32:19Z`; success cleanup counters/summary
were uncollected, so only removal is asserted. This passes the fixture's
installed production-daemon/CLI/offscreen-Qt/genuine-private-vault, restart,
lost-reply, SQLite-only rollback and ownership-uninstall predicates. No user
service, interactive desktop, personal vault or live provider was exercised.
Earlier unidentified `faf6...` cleanup remains unknown. Neo's same-source
archive caller was interrupted after the user's host-role correction at
approximately `18:54Z`; its observed analysis/action times were `18:30:19Z`
and `18:31:03Z`. Local exit 130 does not establish remote termination or cleanup.

The user subsequently directed inspection of ASFW/FireWire, cmux and related
Darwin projects on Neo for their existing Bazel 9+ REAPI dispatch patterns.
Neo source inspection is authorized; new Neo compilation is not. PZM readiness
invocation `de21f692-0fa5-44b3-aed2-3b809f9843c9` at `18:54:44Z` returned
zero and observed only configured SSH alias, Darwin arm64, Nix executable and
store presence. It did not query the Nix daemon or prove a REAPI worker ready.
Current route and matching declared Darwin tool/SDK closure remain to resolve
from the existing consumer examples; endpoint/credentials stay operator-owned.

Interruption exposed a transport defect: a Python caller interrupt could leave
its independently started SSH process group alive. The correction handles
interrupts and boundedly drains only that owned group. Focused invocation
`eadf246f-90dc-401d-8fe6-e5ac0a2e6153` passed the then-current cancellation
fixtures and 21 deployed-runner cases, including real SIGINT with a descendant.
An initial fixed-proof local cancellation invocation
`69370e50-fb88-4307-8a32-cdb6e45e774d` safely rejected the generated Bazel SSH
wrapper before any process scan or signal. Actual declared-wrapper integration
passed under `ee8a7551-ec64-4cc8-9f10-98a56dc25a71` at `19:11:47Z`.
The reviewed primitive accepts only the exact generated three-line wrapper,
its stable regular/nonshared custody and pinned Nix-store SSH executable;
it never evaluates wrapper shell text. Invocation
`4bdf6c5e-2a2a-4070-a22e-8417c214652e` then refused the original 4,096-entry
process ceiling without signaling. The finite ceiling was increased to 65,536;
all exact current-user, executable, Neo destination, proof UUID, session/PGID,
start-time and inode checks remain. Six scoped cases, including the real wrapper
and zero-signal bound refusal, passed under
`691317f3-74c9-4f6b-a497-0414e013d4f8` at `19:13:46Z`.
Final local scan `558961a5-b1d4-4a3d-b0bd-6f28c2ae2bfa` at `19:14:06Z`
returned zero with `absent`, zero matching processes and no signals.
The local fixed-proof scope is closed; remote graph/artifact/log/cleanup remain
unknown. The subsequent complete source graph is still required.

The final scoped recoveries used source
`0be0a6ba61854b608b26bdd3706d122eae0bf427528101d2dffb6ca13101f430`.
Neo proof `ce76120f-efee-4120-ae5b-cfd2fa54fb1b`, orchestration
`f84dd426-23e6-48e1-b2b4-32dc45b0c460`, removed exact `.run-s9jRDq9y`:
35,214 directories, 199,746 entries, zero repairs; summary SHA256
`58150bc9dee2f245d83d4a96d5df0399e56006536dfadcf946462c9730353ea8`.
Remote/local exits zero; fresh `.run-frJxKKOJ` also removed. Bootstrap
`18:23:57Z`, repair `18:24:21Z`. Together with the earlier partial count,
the old workspace exceeded the former two-million-entry ceiling.

Sting's last fixed lookup returned `recovery-no-match` for two candidates and
zero matches: proof `8f4f760e-214e-4160-a2cf-d9b3125c34a6`, orchestration
`22230804-301c-4c10-b92d-06c4655e754e`, remote exit 3/local exit 2,
zero old-directory mutations. Summary SHA256:
`77d59b1df47cd5896455a8750c176ae1c038b8293ffc28f275ab6da6fb2208bc`.
Fresh `.run-t5FoQnzn` removed; bootstrap `18:23:58Z`, reader `18:24:08Z`.
The earlier `faf6...` workspace remains unidentified with unknown cleanup
disposition. No further identity extensions, arbitrary adoption or broad
deletion are attempted. This unavailable identity is retained separately
from the new runtime proof.

Final runtime recipes use the same frozen source: Neo orchestration
`f56bfe97-7da6-4a5e-804c-a8880220d451`, archive target with a new fixed
3,600-second caller; Sting orchestration
`d889391c-2091-4d76-9ef3-3c8c78f45178`, installed-custody target with a
new fixed 1,800-second caller. At dispatch, artifact/log digests, exits and
current-workspace cleanup were pending; Sting's passing outcome is above and
Neo's caller was subsequently interrupted as recorded above. No OS-service, interactive UI, personal vault or provider
evaluation is included.
Neo proof `2acf30f9-a1df-4a57-9231-ad2ee195299e`, fresh `.run-U1ZLg7kn`,
bootstrap `18:26:34Z`, graph `18:26:56Z`; Sting proof
`fb703896-cde8-4cac-a3cb-20cfc5baa6dc`, fresh `.run-7Vx7V1E1`,
bootstrap `18:26:35Z`, graph `18:26:41Z`. Their fixed caller limits are
approximately `19:26:34Z` and `18:56:35Z`; no outcome is inferred from admission.
Post-dispatch documentation/goal gates passed two targets, zero skipped/failing,
under `c3c7c21a-dce8-4ccd-839a-fdc09ae3746c` at `18:28:51Z`, using the
clean locked Nix/Bazel `docs_check` and `docs_guard_test` recipes. Both repository
whitespace checks passed at `18:29:54Z`.

The additional exact-artifact reader, nonblocking authority reads and finite
eight-million-entry ceiling passed independent review. Focused six-suite
invocation `6c27cadc-2d6b-4267-840e-e2cf96cfca5d` passed at `18:17:52Z`:
17 cleanup and 20 deployed-runner cases ran fresh. The actual locked Bazel
output-base observation `2708b356-d128-46cc-a453-3f08405f9080` matched the
canonical workspace MD5 path calculation in declared test invocation
`8a8368bf-ab70-4712-a27d-0d87d2d0326e` at `18:16:34Z` (18 cases).
Artifact path components require current-user ownership, no shared writes,
no symlink traversal and stable descriptor identity. The exact recorded
59,741,174-byte archive must be regular, single-linked and fully hash to
`a49ad024d06d6864097007e4d1c7c0729e9415c830c2cc1427c92680d3e6aa5a`.
Matching proves recorded content/custody only. Missing/ambiguous matches have
distinct fixed categories; they authorize no old-directory deletion.
The integrated frozen source passed **53 test targets, zero skipped/failing**,
invocation `345cb6b9-f49b-4a7f-a572-82e4c67368d9`, at `18:20:17Z`.
All **92 build targets** passed under
`616ad9c8-1a6b-4c7f-9b0c-4938fb9a874e` at `18:21:30Z`.
Declared digest `2fb774b3-e2db-41ad-9752-0dcf246ae2de` at `18:22:18Z`
records frozen source
`0be0a6ba61854b608b26bdd3706d122eae0bf427528101d2dffb6ca13101f430`.
The remaining exact Neo repair (`f84dd426-23e6-48e1-b2b4-32dc45b0c460`)
and final fixed Sting identification (`22230804-301c-4c10-b92d-06c4655e754e`)
use these bytes with separate unchanged 600-second caller limits. Their actual
cleanup outcomes were pending at dispatch; their actual results and the final
Sting composite are recorded above. Neo's artifact composite was subsequently
interrupted; its remote outcome remains unknown, and compilation moves to PZM.

The two-line TreeArtifact correction is independently approved and frozen.
Existing bundle/Mach-O tests both executed and passed under
`dcb4c6bf-58fe-4c65-a58c-e7cab4b55f09`. The fourth exact Neo repair tuple
passed independent review and six scoped suites under
`5c6b639b-8e02-4106-b680-b6a2a448dcfc` at `17:56:21Z`; custody and
original-deadline limits are unchanged. The integrated corrected source then
passed **53 tests, zero skipped/failing**, invocation
`0f3d6cb5-0d88-4f2c-86c4-60c17b1c9f48`, at `17:58:02Z`.
All **92 build targets** passed under
`4dc406e2-e20f-429c-8dc4-901ebf67fb52` at `17:59:11Z`.
Declared Python digest `f14fbe56-57f1-4dbc-b7a8-24152633f7c9` at
`17:59:34Z` records frozen public source
`6de25a74941cef63cd51ba28fed9ae812c7ccdfa45dc9f60eeb836627b43476e`.
The graph commands explicitly supplied their invocation IDs. Actual Mac
archive and failed-workspace cleanup remain separate required receipts.
Only the exact Neo `.run-s9jRDq9y` tuple and fixed Sting proof/log recovery
are dispatched first from these bytes, each with the existing 600-second
caller limit; no other retained workspace is adopted.

Sting's fixed marker/log identification did not admit a unique candidate:
proof `3462b2a6-6e8d-41b2-a29d-eca0ee9ef5e8`, orchestration
`7f8cf3d0-b036-4749-935b-c4a6dff1f473`, remote exit 3/local exit 2,
predicate `authority`, zero mutation counters. Failure-summary SHA256:
`c2c1201b719d6433aedc5fed04ad9a9f0f18e724051156b08666c3fe77829373`.
Fresh staging `.run-eSSsvvdy` was removed; no old directory was deleted.
Bootstrap `18:01:19Z`, reader `18:01:25Z`. That predicate does not distinguish
missing from ambiguous identity, so neither cause is inferred. One additional
identification predicate is under review: the exact recorded Linux artifact
digest/size at its fixed Bazel output path within the same bounded private
candidates. It must require component custody and a unique complete match;
it cannot scan arbitrary subtrees, execute old source or establish independent
proof identity from an artifact digest. If that fixed predicate fails, the
unidentified retained workspace remains untouched.

Neo's exact `.run-s9jRDq9y` repair hit the two-million-entry ceiling before
its 600-second caller deadline: proof
`0ef52da7-9a63-4c82-aa6c-c194d22c7a99`, orchestration
`9e31140a-4859-4103-992f-87b6d714c56b`, observed `18:08:11Z`,
remote exit 3/local exit 2, predicate `entry-bound` at depth 22.
Partial counters are 425,237 directories, 2,000,001 entries and zero repairs;
summary SHA256 `d73052e87c5dd3547599ad499881979b3992fb3dbece13e5bb205492bb562cf4`.
The old workspace remains partially removed; fresh `.run-PRGooKMP` was removed.
This concrete SDK/action-workspace volume motivates a reviewed finite ceiling
of eight million entries. Depth 128, descriptor custody and the original
monotonic caller deadline remain unchanged. The next Mac artifact caller
will have a fixed 3,600-second allowance selected before launch, within the
existing maximum, because the previous graph took nearly 28 minutes before
packaging and its cleanup exceeded the shorter count/time limits. No running
caller is extended or restarted by that accounting change. New source gates
and exact cleanup/artifact receipts remain required.

Independent review approved the cleanup correction: graph and cleanup share
the pre-FIFO monotonic anchor; cleanup uses the recorded original deadline
minus a completion margin, with no new allowance after budget wait. Authority
and deadline markers survive an incomplete ordinary walk. Sting recovery
requires a unique match for the fixed proof or complete recorded log digest
within 32 private top-level candidates, at most 128 MiB per log and 256 MiB
aggregate. Existing UID/mode/link/identity, depth and two-million-entry guards
remain unchanged. Focused six-suite invocation
`8bf74b7c-4aef-4864-86e0-999d16d56bfc` passed at `2026-10-03T17:51:34Z`:
14 cleanup, 20 deployed-runner and 11 graph cases ran fresh; the other three
scoped suites retained their passing input digests.

The subsequent full graph passed 53 tests, zero skipped/failing, at
`17:52:39Z`, invocation `b5ad2905-0410-4d7c-a44f-e55c95b4e254`, and
92 build targets at `17:54:33Z`, invocation
`8c96e9c2-8e58-4f88-8794-50ec615c43f1`. The test ID is recorded by the
dedicated output root's current profile symlink; no Java/environment log was
read. The build explicitly supplied its invocation ID. Both used the same
clean locked Nix/Bazel full-graph commands below. These gates precede the
newly observed Darwin-only packaging correction and do not prove it.

Neo source `2cecd60a850b8034ea078ff63652e1fe838b4d5433966447fdd9d784b0ff1a8d`
returned at `17:54:21Z`: proof `22412e51-546a-4379-bef2-9b164c552e46`,
orchestration `d2135163-9838-490f-b12b-4d701b69b25a`, graph/remote exit 1,
local exit 2, no archive. The app relocation action rejected expansion of
its generated `Omux.app` directory. Both application and archive argument
lists must pass the directory pathname with `expand_directories=False`,
retaining declared TreeArtifact custody. Complete private log SHA256:
`f94b1dd7a5fad77d0641e7f1a165f4f0bdfc030ef4f544d21c8833b22e732a67`.
Cleanup also failed its fixed 20-second deadline: 31,881 directories,
136,442 entries and three repaired read-only directories; failure-summary
SHA256 `dbc00ed86da4f3c6bbd44345639b09b5e54acce8f0cf2a64d89ac452b476314c`.
The exact retained workspace is `.run-s9jRDq9y`, authorized only for the
existing bounded repair path. Earlier SDK/link failures did not recur in
this run; no successful package, installed Darwin runtime or UI is inferred.

### Updated Sting artifact and cleanup failure

Source `2cecd60a850b8034ea078ff63652e1fe838b4d5433966447fdd9d784b0ff1a8d`
ran on Sting under proof `faf6e1f4-a9c9-4dad-9947-1b9424a6c844`,
orchestration `456e3af3-7a74-4b7e-a16f-8bbce102626e`. The graph completed
at `2026-10-03T17:32:34Z` with exit zero and the exact updated Linux archive
`a49ad024d06d6864097007e4d1c7c0729e9415c830c2cc1427c92680d3e6aa5a`
(59,741,174 bytes). Its installed runtime predicates passed. The composite
recipe failed: remote exit 1, local exit 2, cleanup predicate `deadline` at
the fixed 20-second allowance. Partial counters were 48,985 directories,
326,703 entries and one repaired read-only directory. Cleanup failure-summary
SHA256 is `10a71805272f8349bfe8701b22315cea62c1bd0b17544aff81111131732fb302`;
complete private graph-log SHA256 is
`16a33002b13ba56e2f390ab0903c135294398973ba18fdc621243ec11323aff2`.
The receipt was observed at `17:33:37Z`; its current workspace basename was
uncollected. No successful cleanup or passing composite recipe is inferred.

The next tooling correction gives cleanup the unused portion of the original
caller allowance, anchored before bootstrap/budget exchange. It must preserve
the total 1,800-second caller limit, custody/depth/entry guards and narrowly
identify only this recorded failed proof for recovery. No new host dispatch
is authorized before independent review and the declared source gates pass.
Neo's immutable source `2cec...` continues under its original caller bound.

The final combined client/CLI, SDK-stub and third-repair source passed **53
test targets**, zero skipped/failing, under
`b58a58d8-5157-41ea-9ab1-1c66bad2d158` at `2026-10-03T17:02:59Z`.
This includes fresh Qt transport, CLI, installed-custody and relocation gates.
All **92 build targets** passed under `c2dbe0ba-35e7-4ca8-b71f-fe1301a311de`
at `17:04:02Z`, using the same clean locked Nix/Bazel commands below.
New Linux production archive SHA256:
`a49ad024d06d6864097007e4d1c7c0729e9415c830c2cc1427c92680d3e6aa5a`,
59,741,174 bytes and 138 artifacts. It supersedes the earlier Linux artifact
for final client/CLI predicates; the historical Sting proof remains valid only
for its earlier bytes until a new exact installed receipt is collected.
Public source SHA256:
`6ccc7d26a03ef98379cf287cb66bd8951c23d9e26ee62f85f29a12c40b018824`,
verified by declared-Python invocation
`313a0200-3a15-4094-8bcf-8efc4738b6ce` at `17:05:42Z`. The current
Neo third-repair orchestration `57fe497a-470a-45ef-8ac3-365f9d690ed7`
uses these exact source bytes and unchanged 600-second allowance; no new
production bundle is dispatched until its result is assessed.

Third-repair proof `47c21c45-0597-4be2-a7d9-187996f1994e` returned
**failed** at `2026-10-03T17:10:32Z`: remote exit 3, local exit 2,
static category `custody`, fresh staging removed. Bootstrap `17:07:51Z`,
repair `17:08:09Z`. The guarded walker partially removed the old workspace,
but did not establish removal. No partial counters or summary hash were emitted
on exception. Its approximately 142-second run was not classified as a deadline
failure; that duration alone cannot identify the earlier normal-cleanup cause.
At this receipt the root held bundle dispatch and required bounded partial
counters and distinct fixed rejection categories, with guards and budgets
unchanged. The subsequently reviewed classification-only retry below preserves
the uncollected historical cause while checking the remaining exact tree.

The classification-only refinement passed six suites under
`907f91b6-5b13-40c9-ac5c-9ac6d7059e96` at `17:18:03Z`: twelve cleanup
and twenty deployed-runner cases, plus the existing four scoped suites.
Independent review approved fixed predicate codes, retained partial counts,
bounded metadata and canonical failure-summary hashes; deletion guards and
budgets remain unchanged. The preceding `9488bdd0-c21a-48f6-918a-c86d679c5d5d`
passed at `17:16:46Z` before the final prewalk classification refinement.
Fresh source producer `cce7a273-55db-4a6b-a3af-2c88f03a699e` passed at
`17:19:42Z`; digest `0a657f24-1c8c-4874-944f-08e83776c8c2` at
`17:20:36Z` confirmed:
`2cecd60a850b8034ea078ff63652e1fe838b4d5433966447fdd9d784b0ff1a8d`.
Runtime/client inputs are unchanged from the preceding full graph.

The exact enhanced repair **passed**, observed `2026-10-03T17:24:08Z`:
proof `1961c977-a130-475e-a4b8-6f7ec09ab09b`, orchestration
`8132583d-22c0-47c9-95bf-6e15636338f9`, source `2cec...` above,
local/remote exits zero, `.run-tIFiJDX7` removed and fresh staging removed.
Counters: 3,407 directories, 35,288 entries, zero repaired directories.
Summary SHA256:
`5a9eb6b33804f218c8c32398aa13108f9200018479db9fc324bd1478d9f60ee6`.
Bootstrap `17:22:51Z`, repair `17:23:19Z`; exact worker end remains
uncollected. This success cannot identify the prior failed custody predicate:
the previous attempt had already partially removed the tree. No guard or
budget was relaxed and no historical failure is rewritten.

Final dedicated-host recipes now use that exact source: Neo production archive
proof `22412e51-546a-4379-bef2-9b164c552e46`, orchestration
`d2135163-9838-490f-b12b-4d701b69b25a`, and Sting installed proof
`faf6e1f4-a9c9-4dad-9947-1b9424a6c844`, orchestration
`456e3af3-7a74-4b7e-a16f-8bbce102626e`. Both retain normal 1800-second
caller allowances. Neo bootstrap `17:26:10Z`; Sting bootstrap `17:26:11Z`,
graph `17:26:16Z`, mapping `17:26:24Z`, loading/analysis `17:26:29Z`.
Artifacts, log hashes, graph/remote exits and cleanup results remain pending.
No service/UI activation, personal/default vault or provider calls are included.

The generated reference digest was rechecked under
`0c2005aa-9fb0-42ef-b756-9af75619f6b6` at `17:09:00Z`; it remains
`f6467e0f6ebfb0a6ceffeb9be9eccdf006f4d26968caa2a1e1eaf8ae61c44c74`,
matching the previously imported SPA bytes and its passing gates. No deployment.

The combined Mach-O linker and current-workspace cleanup corrections passed
**53 test targets**, zero skipped or failing, under
`5f78e793-af5b-4ef1-bce3-0f1bc9fb7b1a` at `2026-10-03T16:25:51Z`;
**92 build targets** passed under `8cd3cb64-b9ec-4eb0-8cac-e4eaf04c3f18`
at `16:26:22Z`. Declared-Python digest invocation
`e6c019b3-eace-4c63-ac58-8153ebbbde58` at `16:26:49Z` verified the new
public source archive SHA256:
`699298768f2765607fd087c8836e1866f9233be9b438fdbf6b772073eb247914`.
The same clean locked Nix/Bazel commands below were used. Independent review
approved both frozen changes. Focused six-suite gate
`28c699bf-bdc0-415d-b528-60efb07d3a7c` passed at `16:23:42Z`: nine cleanup
and eighteen deployed-runner cases, plus the existing graph/workspace/inventory/
SSH suites. Cleanup uses a real filesystem/FD walker with fixture-only ancestry
substitution in its current-entrypoint tests; it is not a separate-process
cleanup test. Graph custodian-loss testing retains its actual subprocess proof.
The first focused attempt `18d43c9a-94bd-4b15-8f85-b6b52218a7fd` failed from a test's captured default
validator bypassing its intended mock; the explicit test validator was corrected
without changing production custody. Its deployed-runner cases passed; one of
eight cleanup cases errored in the fixture.
Current-created cleanup binds an exclusive private proof marker to device/inode,
rejects historical recovery names and never takes an outer generic fallback once
the Nix child has started. The exact second known repair passed under proof
`2b7163e4-c36d-4235-b9c1-65ce07447b44`, orchestration
`bd1b3493-7247-4f95-b95d-22a841ae58e2`, using the new source above:
`.run-UVJycRK3` removed, thirteen directories and 126 entries, three owned
read-only directories repaired, local/remote exits zero. The fresh staging
directory also removed, exercising the new normal cleanup path. Bootstrap
`16:27:36Z`, repair `16:27:59Z`; bounded summary SHA256
`6539155bb8dc322ab3eed0dbc1a1c68b9d14385b75ee320886659fb46409ba0b`.
Its counters match the first repair, so the summary digest matches; this is
not a full-log digest or proof identity. The new production Darwin archive
still requires its artifact and cleanup receipt.

Sequential production archive proof `e5d3e5f5-7872-4249-926b-de7db20d9632`,
orchestration `8e2a8b6d-859c-49e5-a3c8-5616e3c76685`, uses that same
`699298...` source. Bootstrap `16:29:02Z` and declared graph `16:29:21Z`
were observed within its original 1800-second total caller allowance. The
actual result remains pending; these phases establish no artifact predicate.

The actual receipt was observed at `2026-10-03T16:36:29Z`: graph/remote
exits 1, local exit 2, cleanup **failed**, Darwin arm64 kernel 25.6.0,
no artifact. Full private-log SHA256:
`8537f74eaf4a9b6913a8721cdaf8dfa3d9d9c640213e19346729e53bb836a346`.
Both Zig executable actions at `BUILD.bazel:198` and `:207` reported
`unable to resolve dependency`; the current collector omitted dependency
identities and the normal-cleanup category. The exact known failed workspace
is `.run-tIFiJDX7`, bound to this receipt. Next work is a bounded, hash-verified
read of only that private graph log to return public dependency identities and
static cleanup categories through fresh declared tooling. Old staged source
must not execute. No speculative include/linker bypass, unknown-workspace
adoption or provider/personal-state access is authorized by this failure.

The reviewed reader's six-suite gate passed under
`a61e7a4e-5a9e-4c0a-83fa-72cde53b303c` at `16:45:29Z`: eleven cleanup
and nineteen deployed-runner cases, with the existing four scoped suites.
Fresh diagnostic source producer `44d98e54-a908-4403-a2c6-5f19befdcaf5`
passed at `16:47:12Z`; declared-Python digest
`a9b95b8a-ecb6-40cc-8792-bc6764a410cb` at `16:47:31Z` confirmed
`740e6661d540cb2cc06484b80c08be5ad7d0bc43313abf89907e26cf86604c92`.
This is a diagnostic source snapshot, not final product artifact proof.

The exact read passed under proof `8b2cf6d8-f548-43d6-b3a8-29d21fa1f62f`,
orchestration `b1fb15e8-5e9e-4c3e-a2c2-04dc6d31c42b`: local/remote
exits zero and fresh staging removed. Bootstrap `16:48:14Z`, reader
`16:48:39Z`. The recorded full log hash `8537...` above was verified before
extracting identifiers. Returned category: `unresolved-dependency`;
framework `CoreFoundation`, libraries `libobjc.A.dylib` and `libobjc.A.tbd`,
SDK-relative paths `System/Library/Frameworks/CoreFoundation.framework/CoreFoundation.tbd`
and `System/Library/Frameworks/libobjc.A.framework/libobjc.A.tbd`.
The old workspace and log remained untouched. The next correction declares
the locked SDK's `usr/lib` stubs and search path explicitly; no host library
search is authorized. The failed normal cleanup category was discarded from
stdout and is absent from the graph log, so it remains uncollected. A subsequent
exact repair's counters/category will be a new observation, not retroactive
proof of that failed cleanup's cause.

The dependency correction is independently reviewed and frozen. Explicit
`NIX_ZIG_ROOTOPTS` carries framework and library search paths before root `-M`;
`NIX_ZIG_LINKOPTS` carries trailing linker options. The exact locked SDK
`usr/lib/libobjc.A.tbd` must exist and appear in the finite declared stub
filegroup received by every Zig action. Linux loader/rpath arguments remain
unchanged; Darwin keeps `-fno-lld` after dependency flags. Both changed Linux
production link actions ran and passed under
`5f1e5999-cad6-47a8-9837-76173b576d99`. Actual Darwin linkage is still
required. The third exact repair tuple passed independent review and six-suite
gate `cdfb13ba-a5b4-4101-a3a4-0d33ee777790` at `16:51:20Z`; its actual
host result/counters remain pending.

The reviewed Zig-link and cleanup correction passed **53 test targets**,
zero skipped or failing, under `91d2f6d5-67d5-48de-ade4-57dc06a25e0f`
at `2026-10-03T15:59:55Z`; **92 build targets** passed under
`67b99533-5ceb-4acb-bcc8-fe094f4e6660` at `16:01:04Z`. Exact new public
source archive SHA256:
`9876183412758f2e0546bdaf545f7d278b0181128e5f1313df9b80fb5ddc3292`,
verified under `92b22829-3aa9-4e2b-be62-d53f70b1e6fb` at `16:01:52Z`.
The final Zig action receives the exact locked SDK framework search path before
the root module, and the finite framework filegroup is an explicit action input.
It introduces no host SDK search or include-validation bypass. Independent
review approved both the link declaration and fixed-workspace cleanup walker.
Focused six-suite invocation `50855d44-7e32-48ff-8faf-ae9dc48a65d5` passed
at `15:57:04Z`. Directory repair is restricted to opened, owned directory
handles; it rejects shared-writable directories and never follows or chmods
symlink targets. A repair receipt hashes its bounded summary, not a full log.
The exact known-workspace repair passed under proof
`c53b84fa-4b82-4690-841c-2570a7eac263`, orchestration
`1077f4b8-3298-4384-a1b2-97b2b9625464`, using source `987618...` above.
The solely authorized old workspace `.run-nUi7wZna` was removed: 13
directories, 126 entries and three owned read-only directories repaired.
Remote exit zero; fresh staging also removed. Bootstrap was observed at
`2026-10-03T16:02:37Z`, repair at `16:02:59Z`. Bounded repair-summary SHA256:
`6539155bb8dc322ab3eed0dbc1a1c68b9d14385b75ee320886659fb46409ba0b`.
This digest covers the bounded JSON summary, not a full log. Authority came
from the exact previously observed basename and validated private custody;
the old directory was not treated as source authority. No siblings, personal
processes or symlink/store targets were touched.

The corrected production archive uses the same exact source under proof
`3ddc3001-8494-4fb1-bfdb-4f3676d15684`, orchestration
`2b9df463-469b-4772-bbee-dc56821d5d81`, target `//clients/macos:archive`.
Its normal 1800-second caller allowance includes transfer and bootstrap;
bootstrap `16:06:04Z`, declared graph `16:06:24Z`, mapping `16:06:29Z`, loading/analysis
`16:06:33Z`, analysis complete `16:08:39Z` and action execution `16:08:48Z`
were observed. These metadata phases are not artifact acceptance. The actual
archive digest/size, graph/remote exits, private-log digest and cleanup receipt
were required before acceptance. No UI or service was activated.

That archive returned graph/remote exits 1, local caller exit 2, cleanup
**failed**, Darwin arm64 kernel 25.6.0, with no artifact. Full private-log SHA256:
`c0caf942f58e6da6ab5fd9e4ae5fef63a63509e8fe109d02276eda03f98f57d0`.
The Zig executable actions at `BUILD.bazel:198` and `:207` reported
`using LLD to link macho files is unsupported`. The new known failed workspace
is `.run-UVJycRK3`, authorized solely by this observed proof receipt. The exact
Darwin linker declaration needs correction while retaining Linux linkage and
SDK input custody. Two actual read-only-directory cleanup failures now justify
using the guarded directory walker for the runner's own newly created staging
workspace, with creation identity retained. This cannot authorize adoption of
unknown historical workspaces. Review, declared local checks, exact known repair
and a new production archive receipt remain required.

The narrow Mach-O correction is independently reviewed: Darwin emits
`-fno-lld` as the final link option, after the pinned rule's dynamic-dependency
`-flld`, while the exact framework root remains before the root module.
Linux options and declared SDK inputs are unchanged. Targeted Linux production
daemon/CLI build `c1e19bb0-a4d9-4b11-b388-bbb2f4c73a83` passed; this does
not establish Darwin linkage. The guarded cleanup correction retains a private
current-proof marker and workspace creation identity, and removes the generic
fallback after declared cleanup has begun. Its focused check and actual host
outcomes were pending at that review; the final integrated gate above passed.

The corrected-runner graph passed all **52 test targets**, zero skipped or
failing, invocation `d0c02cc2-e4fe-4809-b2a7-22b3ab053d5c`, completed
`2026-10-03T14:55:20Z`. All **91 build targets** passed under
`bdea5b80-fd4e-49d4-8501-2877476dd3a7`, completed `14:55:45Z`, using the
same clean-environment locked Nix/Bazel commands below. Only host tooling and
its declared tests changed; production runtime and SPA reference facts remain
at their previously proved inputs. Independent review approved the deadline
correction and bounded metadata-only phase watcher. Focused invocation
`a6369ab7-f122-4ddf-aaf5-aee87daae2d4` passed five suites at `14:50:54Z`,
including ten worker cases with real subprocess cancellation and seventeen
deployed-runner cases with actual declared Bash syntax checks.

The new public source archive SHA256 is
`d284c4601b62082cf12620564707bdf5357243c547d29dff5719242729f74039`,
verified with the declared Python tool under
`2443062f-9ded-4742-bc18-b51b8b2e98bc` at `14:56:04Z`. A single Neo
private-Keychain diagnostic uses this exact source with a 600-second total
caller allowance including bootstrap; it does not extend the earlier calls.
Its final disposition must be recorded before platform acceptance is assessed.
The transfer completed before Nix bootstrap at `2026-10-03T14:57:04Z`.
Proof `1a14710d-ccf2-4640-bf8c-91502c6a253c`, orchestration
`13703b7c-1749-43a5-a409-8d099aa6c87c`, has an original caller deadline
approximately `15:07:04Z`; later local prose changes do not alter its payload.
Observed phases are Nix bootstrap `14:57:04Z`, declared graph `14:57:45Z`,
repository mapping `14:57:48Z`, loading/analysis `14:57:53Z`, analysis complete
`15:00:11Z` and action execution `15:00:19Z`. These are metadata-only phase
observations, not the private Keychain target result. The final result,
private-log hash and cleanup remain required.

That diagnostic returned at `2026-10-03T15:06:35Z`, before its deadline:
graph and remote exits 1, cleanup **removed**, Darwin arm64 kernel 25.6.0.
Full private-log SHA256:
`8a4191a48344689994ed15a1aa04a70cb25d0f9fbb0f5fd7ee6076a5448ebb54`.
Both `src/platform/vault_bridge.c` and `src/platform/vault_realproof.c` failed
under `BUILD.bazel:167:10` with `absolute path inclusion(s) found in rule`.
The Keychain test did not execute. The current collector omitted the header
continuation lines, so the exact rejected header identity is unknown. Review
found that the declared Darwin builtin include roots omit the locked SDK's
framework subtree used by these sources; this is a cause hypothesis until
the corrected graph supplies proof. No include-check bypass is authorized.

The `15:07:56Z` five-hour checkpoint therefore remains **partial**: source
52/91 and Linux installed predicates passed; the actual Darwin implementation
failure remains open. The active goal continues with the narrow declaration
fix, independent review, necessary Linux checks and a new exact Darwin receipt.
Deadline passage does not complete required work or turn a source failure into
host unavailability.

The reviewed correction adds exactly the locked Apple SDK's
`MacOSX.sdk/System/Library/Frameworks` subtree to builtin include declarations,
with Darwin-only `-iframework` lookup. Ordinary Linux include order and Bazel
validation remain unchanged. Targeted Linux bridge compilation/test passed
under `3c9257fa-fe92-4bbe-8c99-0652e4391b65`. The complete corrected graph
again passed **52 tests**, `f1c5527a-7710-4e25-911a-015eca20cdd8` at
`15:13:18Z`, and **91 builds**, `c538f2c0-4ead-4ad7-a7e3-45f187ed0036`
at `15:14:59Z`, through the same clean locked Nix/Bazel commands. New source
archive SHA256:
`db31f7e514c86078689b957fff03cd0ce5a3ce0a1836f609412d7df18817307b`,
verified under `698da9df-2132-42fb-bd14-1135f1b82c03` at `15:15:40Z`.
The Neo private-vault rerun **passed** under proof
`2054eb40-8f4f-4009-b7ab-12a190a89e85`, orchestration
`b114fa76-4ba3-4f6f-b9ec-1a0750f826d4`: graph and remote exits zero,
cleanup removed, Darwin arm64 kernel 25.6.0. Receipt observed by
`2026-10-03T15:26:52Z`; the original 600-second caller bound remained intact.
Full private-log SHA256:
`e46d72a7018ef4a8a04d2ac219459606e906580ca7dd0038290ec1a8d924f093`.
Phases: bootstrap `15:16:49Z`, declared graph `15:17:17Z`, mapping
`15:17:21Z`, loading/analysis `15:17:27Z`, analysis complete `15:19:29Z`,
actions `15:19:35Z`, graph complete `15:22:16Z`. This establishes actual
private macOS Keychain driver IO and confirms the narrow declaration fixes
the observed compile failure. It does not prove personal-session custody,
production Darwin daemon installation, SwiftUI operation or OS-service lifecycle.
The partial five-hour checkpoint and earlier failure retain their history.

A sequential production Darwin archive build uses the same source under
orchestration `61f9cfe2-5b61-484e-9b4d-7cae27ec5a0f`, with the normal
1800-second recipe allowance, inside the unchanged maximum 3600 seconds.
No UI or service is activated and no personal state is accessed. Its exact
artifact/result/log/cleanup receipt returned at `2026-10-03T15:38:37Z`:
graph and remote exits 1, cleanup **failed**, no archive artifact.
Proof `14ccacec-4922-486d-a95f-4332d4f531bb`; private-log SHA256
`c7471d9ee235ca7edf9f310c03186fd0ad7b37c49b5d1192949fc5df65bbfa9f`.
The Zig executable actions at `BUILD.bazel:198` and `:207` could not find
Security or CoreFoundation, reporting no framework search paths. C builtin
declarations now work; Zig's distinct link invocation still needs the exact
declared SDK framework search root. The known private workspace
`.run-nUi7wZna` is the sole cleanup-repair scope; no other workspace or personal
process is authorized for inferred deletion. Narrow fixes, review and actual
new proof remain required before completion.

The preceding full test invocation `e74c4393-78bc-450e-ab10-0827d0ba0e4d` completed at
`2026-10-03T13:43:07Z`: **51 test targets, zero skipped and zero failing**.
Build invocation `269155db-aa8f-4737-a7bb-829a97ce22f9` completed at
`2026-10-03T13:44:40Z`: **90 selected top-level targets** passed. The graph
includes the final source self-documentation, strict inventory, host-custody
helper, hardened transport and 29-case documentation guard. Both commands use
`nix develop --ignore-environment --keep HOME --command bazelisk --nosystem_rc --nohome_rc --output_user_root=/srv/fast-local/jess/state/codex/omux-native-safety-proof-20261003`,
followed by `test //... --keep_going --jobs=4 --test_output=errors` or
`build //... --keep_going --jobs=4`. Later receipt prose is checked separately
after tracker reconciliation; it cannot change compiled predicates.

The final production Linux archive SHA256 is
`15d301a314df93205feeee5c3d3a3bf923711422c9f6df4c3842a9e57f28bbc1`,
59,741,283 bytes, 138 artifacts. Actual installed custody and relocation passed
for these bytes under the preceding integration invocation below; those exact
predicates remained passing in the complete graph. They retain their private
prefix, genuine isolated vault, actual daemon/CLI/offscreen Qt and no-service
activation bounds.

The final host source archive from the full build is
`68ce17382788c6325f754a0a3709a33182840755c5e1ff13967d0fc214c3d6dd`,
verified under `49ad0b06-395b-4c3c-8979-11cec5257a38` using the declared
Python tool. Sting installed orchestration `fd1c0f05-ea7e-4956-99f6-76df5ac67478`
passed, proof `646d1279-4c74-4a09-b1b4-8714f24fd730`: graph/remote exits zero,
Linux x86_64 kernel 6.12.0, cleanup removed. Full private log SHA256
`06b5286d16a6206807be078d0135d6aa734e40c141d7810397e11df09107a344`.
The actual artifact SHA256/size exactly match the final local archive above.
This proves the final durable host runner and isolated installed predicates;
personal-session custody, user-service activation and live native/provider
continuity are not included.
Local SSH orchestration retains only actual HOME and existing SSH_AUTH_SOCK;
the agent is never forwarded to the host.

The same source epoch's two Neo recipes admitted private durable directories,
reported Nix bootstrap at `2026-10-03T13:53:13Z` and reached the declared graph
by `2026-10-03T13:54:49Z`. Bundle orchestration
`8f8fd1f2-3b5f-4b42-b7d7-b98d70fbc93f` uses proof
`caf51e7d-acbc-4d9f-8d3e-1734458b6287`; private-Keychain orchestration
`7510a58a-7a2d-40ca-9608-2cdb769cfc44` uses proof
`e5c8304d-89cd-42c8-81b6-2bf4183d21f6`. Both callers expired at
`2026-10-03T14:53:13Z`–`14:53:30Z`, exit 2, without a graph exit,
private-log digest, artifact or cleanup receipt. Their last observed phase was
declared graph admission; later execution phase and remote cleanup remain
unknown. This supplies no Darwin acceptance proof.

The five-issue/NS5 Linear reconciliation is now verified in
`docs/tracker-updates/native-safety-sprint-2026-10-03.json` under
`final_linux_host_epoch`. TIN-5337 is Done for the reviewed component; the
four broader issues remain In Progress, unassigned, with unchanged dependencies.
The local goal ledger marks graph/reference/tracker reconciliation passed
while keeping installed-platform disposition independently in progress.

The observed Nix bootstrap exceeded the runner's 20-second reserve. Its caller
bound begins before bootstrap, but the graph's 3580-second bound begins after
bootstrap; the caller can therefore expire before graph diagnostics and cleanup
return. This is a confirmed deadline-accounting defect, not evidence of the
current graph's execution phase. A bounded correction and private-log phase
watcher passed review and validation above, without changing the earlier
source epoch or extending its bounds.

First corrected-runner full graph `eb6f75ec-382d-4242-9e6b-b07d2af33c4e`
completed at `2026-10-03T14:53:16Z` with 51 of 52 targets passing. Only
the documentation contract failed: the new passed ledger entries omitted
their already-executed command fields. Those fields are restored from the
existing exact receipts; no guard or execution requirement is relaxed.
The follow-up `dd8abadf-83ba-467e-880a-e6fbbe3656e1` at `14:54:36Z`
also had 51 of 52 passing; its documentation guard caught an unsupported
evidence-class label. The reference receipt now uses the declared `document`
class, preserving its exact invocation and purpose.

## Earlier durable-output integrated graph

This full graph includes the optimized strict inventory and precedes the final
self-documentation and durable host-staging changes. Cold test
invocation `998a3d8a-11a8-4895-87f9-520f534eb465` completed by
`2026-10-03T13:13:06Z`: **50 test targets, zero skipped and zero failing**.
Build invocation `2aa6f635-b31b-4d23-a2ba-442839e7bfc0` completed at
`2026-10-03T13:13:58Z`: **89 selected top-level targets** passed.
Both use
`nix develop --ignore-environment --keep HOME --command bazelisk --nosystem_rc --nohome_rc --output_user_root=/srv/fast-local/jess/state/codex/omux-native-safety-proof-20261003`,
followed by `test //... --keep_going --jobs=4 --test_output=errors` or
`build //... --keep_going --jobs=4`. Actual HOME is preserved; other inherited
environment values are removed before Bazel startup. Tools come from the locked
flake and home/system rc files remain disabled.

Earlier temporary output roots repeatedly lost original `rules_zig` archive
files between invocations, while newly patched files survived. This prevented
repository mapping and is an output-cache custody failure, not a passing or
failing source predicate. Read-only diagnosis found that the running
`tinyland-cleanup` 0.4.1 service recursively age-cleans `/tmp` and `/var/tmp`
using preserved file modification time, without honoring fresh extraction
times or Bazel locks. The deletion pattern matches that policy; no deletion
event trace was captured, so causation remains an inference. The private
durable output root avoids this policy without changing the host service,
actual HOME or system configuration.

The final host runner uses strict per-user durable staging, preserves actual
HOME, validates its full ancestry before creating anything or starting Nix, and
rejects unsafe existing directories without chmod adoption. Nix bootstrap and
the resulting devshell both remove inherited environment values except actual
HOME and explicit private XDG directories. Local SSH subprocesses have an owned
process group, bounded timeout drain and fail-closed stdout collection.
Independent read-only review approved the frozen sources. Focused receipt
`3860f7b6-110e-449d-a2f6-e098802e6636` passed six workspace, 16 deployed-runner,
10 inventory and five SSH-policy cases, including subcases. A declared real
Linux Bazel action with workspace/output paths containing spaces passed under
`2cf089d2-4a7e-4c8f-acb3-bb46f398c3bc`; this does not establish Darwin execution.
The earlier analysis/filegroup-only spaces probe
`65c580ed-5b31-498d-8df8-c34cbdfb2b3f` is superseded by that action proof.

Final integration invocation `98d12cef-0213-4657-9626-ca89af99b815` completed at
`2026-10-03T13:42:39Z` with **50 passing tests and one failing documentation
gate**. Its command allowlist rejected the new exact clean-environment Nix form.
The guard now accepts that form explicitly and tests rejection of additional
environment-retention flags; no execution rule was relaxed. The changed
production archive passed installed custody and relocation in this invocation:
SHA256 `15d301a314df93205feeee5c3d3a3bf923711422c9f6df4c3842a9e57f28bbc1`,
59,741,283 bytes, 138 artifacts. The final complete graph above supersedes this
failed documentation gate.

## Earlier corrected integrated graph

At `2026-10-03T12:37:57Z`, the full test graph passed **50 test targets,
zero skipped and zero failing**, invocation
`4e03c38d-ccca-41f7-9ac1-a6e682151fa7`. At `2026-10-03T12:38:28Z`,
the full build passed **89 selected top-level targets**, invocation
`24e4ccf3-54a3-48c2-b501-0acc3c4eda2f`. Both commands used
`nix develop --command bazelisk --nosystem_rc --nohome_rc --output_user_root=/tmp/omux-delivery-scope-final-20261003-0814`,
followed by `test //... --keep_going --jobs=4 --test_output=errors` or
`build //... --jobs=4`. The flake supplies Java; home/system rc files and
unrelated output caches are excluded. Cached predicates preserve their declared
input digests; actual changed production predicates ran under the gate below.

The actual archive, installed-custody and relocation gate
`3c60ea31-26ec-4cc2-ace8-12c5252d8c70` passed at
`2026-10-03T12:36:27Z`. Installed custody ran for 11.2 seconds and relocation
for 10.9 seconds. Archive SHA256 remains
`62690def797ab2c9c57fe23498d4559d43c87cbab90c21c4a8c8f5a6a3ef55b1`,
59,741,335 bytes, 138 artifacts. The corrected packer preserves intermediate
aliases from declared inputs when Bazel flattens symlinks; requested dependency
paths receive no filesystem resolution. Focused regression receipt
`dd283943-a395-4964-a1d2-bfb5a98a1c68` passed 37 portability and 25 delivery
cases. Independent read-only review found no remaining source blocker.

This is experimental Linux source and private installed proof. Darwin production
targets remain platform-incompatible with the Linux graph; their passing policy
fixtures do not establish Darwin compilation or installation.

## Earlier core graph

At `2026-10-03T11:19:05Z`, `nix develop --command bazelisk test //... --keep_going --jobs=4 --test_output=errors`
passed **49 test targets, zero skipped and zero failing**, invocation
`cf662289-d49f-4beb-bf51-f91719a12fc9`. Cached predicates retain their exact
declared input digests; changed engine/actor/adversarial, relocation, policy and
format gates executed in this graph. The integrated actor suite has 16 cases,
including an actual SQLite writer refusal followed by poisoned-custody outcome
refusal, installation-bound capability isolation, request ordering, expiry and
restart authority. The daemon/socket adversarial gate exercises actual workers
with synthetic enrolled grants; it is not a provider or native continuity test.

At `2026-10-03T11:20:20Z`, `nix develop --command bazelisk build //... --jobs=4`
passed **88 selected top-level targets**, invocation
`895a9ebb-08da-4954-a8c4-f47d2a8f76e6`. Linux skips platform-incompatible
Darwin production targets; its passing Mach-O/bundle tests are policy fixtures.
The experimental Darwin minimum is now macOS 14.0, matching the locked Nix
runtime closure; dependencies above that minimum fail bundle validation.

The selected production Linux archive SHA256 is
`62690def797ab2c9c57fe23498d4559d43c87cbab90c21c4a8c8f5a6a3ef55b1`,
59,741,335 bytes, 138 artifacts. The installed-custody test passed for these
declared bytes and remains passing in the frozen graph. Its isolated proof is
placement plus real daemon/Qt/vault IO, not OS-service activation, interactive
desktop, clean-machine compatibility or enrollment of real provider accounts.
Product provenance remains dirty `unversioned-development-source`, experimental
`0.2.0-dev`; no publishable artifact is asserted.

## Superseded exploratory graph

The first full sprint invocation `01481060-6bac-4bd7-a369-bdf47b02e9f6`
found an unformatted mutation file. Declared formatter receipt
`2a020e1d-0a8f-4610-8ce7-36f2a5976d6b` corrected it. This first graph is
superseded by final source corrections and is not the completion receipt.
Invocation `a74f937b-85e6-4b5d-9d61-f3474527d5e4` then found a test-only SQL
module import typo; it passed 45 targets but four failed to build. The import
was corrected to the existing declared `c` module before the frozen passing
graph. No dependency or admission boundary was weakened.

Earlier ratification/source receipts are historical baselines, not proof of
the changed sprint graph. The 49-target graph predates the host-driven build
fixes below; its core predicates remain applicable, but a new complete graph
receipt is required for the changed tooling and packaging.

## Dedicated-host findings

Readiness identified Neo and Pzm as Darwin arm64 hosts and Sting as a Linux
x86_64 host. Yoga lacked existing accepted host-key trust; no trust enrollment
was attempted. All staging uses the public-source archive, private XDG state,
the existing HOME and locked Nix/Bazel. Personal vaults and OS services are not
part of these checks.

| Source archive SHA256 | Host / predicate | Proof UUID | Observed result |
| --- | --- | --- | --- |
| `ba7482c474aee54f29a84b230cc63f4ba38c447da42b64e77215659c51fa405e` | Sting, isolated genuine Secret Service | `1875894a-d49b-4b77-9dc8-c67e509f805b` | Passed; full private log SHA256 `b34076cf29f11b75f00e6b74abebdedade2441891579043698550d54efb4f98b`. No installed or native claim. |
| `8a8adb85116cf5011822c50432ed33d05e473029766c65323260d32747164c9e` | Sting, isolated genuine Secret Service | `5a318a1b-d221-4b26-a7d1-6e3aa6ff28ad` | Passed; Linux x86_64, numeric kernel 6.12.0, cleanup removed; log SHA256 `120ea172bff8c33f84e468c06e97e86cc8a9e0b3cd589ab56859f7265147f121`. |
| `8a8adb85116cf5011822c50432ed33d05e473029766c65323260d32747164c9e` | Sting, installed-custody graph | `e3dbf03b-70a8-41a0-a8bf-0c4c46764787` | Failed before installation: packaging merged unequal CLI and Qt `libsqlite3.so.0` candidates. Graph exit 1, cleanup removed; log SHA256 `11cfa41622e034293dffffee51b5532b643ce45ba1c3ddf45e625cee824ca9f9`. |
| `8a8adb85116cf5011822c50432ed33d05e473029766c65323260d32747164c9e` | Neo, Darwin archive graph | `d9d7f0da-f031-4d2b-bb4b-858c59885501` | Failed Bazel startup with undeclared system Java dependency; graph exit 36, Darwin arm64 kernel 25.6.0, cleanup removed; log SHA256 `993b3453b29c44371a09337566534a6047da3d47f42df41f9ff348ad4a740fa8`. |
| `3db3b7bd606b025be006cb3b9e99ff71192ad086d0ad3bc1a289f2a790af0d0d` | Neo, Darwin archive graph | `e7536484-f4f5-4c08-bef1-a6b86a7826ac` | Declared Java reached graph analysis, which failed recursive SDK symlink traversal; cleanup removed; log SHA256 `7cd79efa44b70420bf42f5141def122863930b47662e3919eb7e31d8b673947e`. |
| `3db3b7bd606b025be006cb3b9e99ff71192ad086d0ad3bc1a289f2a790af0d0d` | Neo, private macOS Keychain graph | `441a92ab-1d8f-4c0b-972d-0ccb4fd0b64c` | Same SDK analysis failure before vault execution; cleanup removed; log SHA256 `7783fe6d2c2efa154ce8959bd138ad8f75256ac26d116fd8b8d7e2b479dc7259`. |
| `3db3b7bd606b025be006cb3b9e99ff71192ad086d0ad3bc1a289f2a790af0d0d` | Pzm, private macOS Keychain bootstrap | `514d438c-3bb5-4960-a064-e8ed952e32b9` | Nix daemon disconnected during bootstrap; no graph or vault execution. Cleanup removed; bootstrap stderr SHA256 `500888a8956f190d012d6e296da9e86263d713a09c5237b30710b6001157c3c1`. No global daemon restart attempted. |

The host failures required three source fixes: an explicit locked JDK for Bazel
startup with home/system rc files disabled; finite closure enumeration that
preserves SDK framework aliases while rejecting undeclared filesystem targets;
and separate dependency candidates for the CLI and Qt runtime namespaces.
The closure excludes only the exact immutable systemd 260.1 aliases to
`/etc/environment`, recording their metadata without reading operator
configuration. Passing focused and full graph receipts are recorded above.
No failed build supplies an installed or Darwin support receipt.

Focused tooling receipt `e26f8351-723d-46de-a654-f4b1b3d7bc7b` passed
`//tools:nix_file_inventory_test //tools:deployed_fixture_test //tools:ssh_policy_test`
with home/system Bazel rc files disabled, an explicit locked JDK and a private
output user root. Eight inventory, 12 deployed-runner and five SSH-policy cases
passed, including subcases. Actual closure enumeration succeeded; undeclared
symlink hops, plain-directory re-entry and aliases that change `..` resolution
are tested. Repository enumeration uses the declared Python with `-I -S`.
Read-only independent review found no remaining source blocker.

Focused delivery receipt `eb6a54a9-b5bc-49b1-a3d8-34b1ae7ef62a` passed
36 portability and 25 delivery cases. CLI and Qt inputs are separate; unknown
absolute dependencies and undeclared aliases cannot acquire provenance through
host path resolution. The passing unit fixtures did not replace the required
production archive check.

Full graph receipt `aa01a4d0-cdd4-40e8-af98-77d879156593` completed at
`2026-10-03T12:28:44Z` with **48 passing tests and two failing to build**.
The production archive rejected ambiguous Qt `libgcc_s.so.1` candidates before
the installed-custody and relocation tests could execute. This is a failed
completion gate, despite passing daemon/actor, vault and inventory predicates.
The corrected integrated graph above supersedes this failure. The cause was a
declared gcc split-output alias lost when Bazel flattened the file symlink;
preserving that intermediate input alias restores the exact RPATH selection.
No arbitrary library winner or host-path fallback was introduced.

Public archive `0761c08c6062cdc72618a424f174fc43c1dbfea7f6589082c25fe04161fa393d`
was built under `7c91a98f-9c1d-4868-a9d5-2c845c7198fd` and hashed under
`57b1553e-a0b4-4329-8460-5c05ed415421`. Four dedicated-host recipes use
these exact bytes: Sting installed/vault and Neo Darwin archive/private Keychain.
Sting results and the Neo inventory-timeout results are below.
The epoch includes the reviewed tooling fixes but
remains exploratory for the production Linux archive until its ambiguity is
resolved and the changed production graph passes. Its Sting vault recipe passed:
proof `b25a8565-2d49-4505-ac7f-ba5e528b5d00`, orchestration
`8819b0b9-a71a-43a0-8174-f416f93c3b7f`, Linux x86_64 kernel 6.12.0,
graph/remote exits zero and cleanup removed. Log SHA256
`ffbc0394f676a9670c648f03b6e3e8512814a0962aa2184ae952b29adbc80c44`.
The same epoch's installed recipe failed with the known libgcc ambiguity:
proof `0a99bfd8-5296-4fde-91c5-d3c4734d3578`, orchestration
`1f4ad13e-e803-4a74-bf19-53a1565d4c13`, graph exit 1 and cleanup removed;
log SHA256 `80bc1870e3503923ad7b4f5258d03b92fa4a90eacfe928d7caefaf47fbabdaf4`.

The corrected public source archive is
`c95c42650f8c76fc2f2a8161260bc9d87272bcfff27b6665ba7892db8b530ff1`,
build `86c89e0d-6d38-4b05-b4d9-ebbc98912c50`, digest
`46fd5940-bce3-474a-8ad2-af48fac5f9a2`. A single Sting installed rerun
uses these bytes, orchestration `2eb93ce3-02bc-4cb3-88d1-c71dd113448f`.
It passed: proof `c14e7aa7-2ff0-460e-92d3-a2ced3fd016e`, graph/remote exits
zero, Linux x86_64 kernel 6.12.0 and cleanup removed. Log SHA256
`eb4fb7b295a5d8e5aaf5215d628198cb996f571a05f14da3a855bd8fa32093be`.
The actual declared archive SHA256 is
`62690def797ab2c9c57fe23498d4559d43c87cbab90c21c4a8c8f5a6a3ef55b1`,
59,741,335 bytes, identical to the local production artifact. This dedicated-host
receipt proves the installed fixture's daemon/CLI/Qt/vault, restart, rollback
and ownership-uninstall predicates, without activating the user service or
using personal credentials.

Neo's two `0761c08...` recipes failed the 600-second inventory limit before
compilation: archive proof `4d70e821-1f2a-4c63-bd2a-87f643c8957d`, log SHA256
`92404b22dfc6cb390e35e8f833333de18be682b89f092be45917c6af1e791d20`;
private-Keychain proof `8f03d778-2408-4aac-a670-0847dab7d8be`, log SHA256
`f7986e92e6de66625c2dc0d4c12144d15ab0fd52af199db1cbcebb2d581caf5e`.
Both graph exits were 1 and cleanup was removed. No Darwin compile or vault
predicate executed in these receipts.

The inventory now caches admitted immutable directory parents and exact hop
costs, preserving component custody, raw alias/`..` semantics, ancestor-cycle
checks and each logical SDK label. The timeout remains 600 seconds. Independent
read-only review found no blocker. Scoped receipt
`6c39b538-f20c-4210-ae87-fce19ce658a0` passed all three tooling suites:
10 inventory cases, 12 deployed-runner cases and five SSH-policy cases.
Actual local strict enumeration took approximately 46 seconds; the complete
scope took 61 seconds, compared with approximately 290 seconds for the prior
enumeration. This is a build-fixture observation, not a product SLO result.
The durable-output full graph above includes this optimization. Public source
archive `d1d1ef0d5f6b6efa04251bf6d77b92bbf39636cbc2c6e5d54e00d9c0aad95883`
was built under `dc5d7842-c6db-481a-a1e1-1d4fa79e85ee` and hashed under
`f73b1ce9-e077-46c5-a1c9-4ca684705030`. Neo archive orchestration
`06d84e4b-18ee-4356-b268-3d23cf8b949a` and private-Keychain orchestration
`dd185377-c72c-4114-acda-85c8b7e8b858` exceeded their original caller bounds
at `2026-10-03T13:52:36Z`: bundle proof
`4eb528f6-3420-4a8b-95dd-896c77f67264` and private-Keychain proof
`83adc9a3-b284-491e-b97e-19eecd55eb00`, caller exits 2. The old runner returned
no graph phase, log, artifact or cleanup receipt. Their phase and remote cleanup
remain unknown; no Darwin predicate is inferred. The revised runner's final
epoch above reports stages directly. Its unchanged 600-second enumeration bound
must pass before Darwin predicates can execute.

## Remaining proof boundary

Live native continuity remains blocked by exact supported upstream hooks and
authorized provider evaluation resources. Browser production exports remain
disabled. OS-service activation, interactive desktop behavior, the production
Darwin archive and Darwin daemon installation require their own passing receipts.
The private Darwin Keychain C driver has its separate compile/IO receipt above.
The installed Linux
test uses a disposable genuine Secret Service, private prefix/XDG state and
offscreen Qt. It preserves actual HOME as a declared input, without personal
credential discovery or OS-service activation. Ledgers have bounded lifetime capacity and
no automatic retirement; full-user backup rollback remains outside the separate
SQLite authority guarantee. No achieved SLO or contractual SLA is asserted.
