# Native reset implementation and evidence — 2026-10-02

This record describes the experimental native reset on `codex/omux-native-reset`,
starting from `f5f83c1ad99c2920de6759791b327a99a02a2ec5`. It records implemented
boundaries, executed predicates and remaining gates. It does not promote the
successor to a release or transfer historical live evidence to new code.

The active design is [the native account-lifecycle reset](../plans/omux-native-account-lifecycle-reset-2026-10-02.md).
Subsequent contract, tracker, documentation-guard and SPA changes are recorded in
[the ratification push evidence](ratification-push-evidence-2026-10-02.md).
The receipts below remain the implementation baseline; later documentation gates
do not promote native or platform support.
Stable v0.1.15 remains governed by its release and retained evidence. An unstamped
successor identifies itself as `0.2.0-dev`, experimental, with
`unversioned-development-source` and `sourceDirty: true` provenance.

Final local validation passed all **37 Bazel test targets and 66 build targets**.
The development SPA passed all seven gates. The native Codex candidate passed
eight production builds, 64 focused Rust cases and 318 protocol cases, with one
intentional upstream ignore. The actual Linux archive passed relocation checks.
Live continuity, real OS-vault IO and macOS execution remain unrun; the exact
commands, receipts and limits follow.

The frozen local graph passed all 37 test targets and built all 66 targets.
Native Codex candidate compilation, focused Rust predicates and exporter
reconciliation passed separately; the development SPA and relocated Linux
archive passed their stated local gates. Live provider continuity, real OS-vault
interaction, macOS execution and publication remain unrun.

## Replacement boundary

The baseline contained 96 files under `src/`, 93 under `scripts/`, 11 examples,
five distribution files and one schema. The legacy runtime and execution graph
were removed rather than carried into the replacement. New implementations may
reuse a filename such as `src/main.zig`; that does not preserve its old module.
`build.zig`, `build.zig.zon`, `build.v02-exact-rebuild.zig`, `justfile` and the old
generated release manifest were removed. The three executable test roots directly
under `test/` were removed with their graph.

Nine automatic workflow files and the private GF checkout action were removed.
Issue templates remain. The retained historical corpus contains 41 files under
`test/fixtures/`, 127 under `test/evidence/`, and 64 under `docs/evidence/`:
232 historical fixture/evidence files. These files are retained as historical
inputs, not executed as successor proof.

## Declared tool and execution inputs

At this October 2 checkpoint the graph pinned Zig 0.17.0, Bazel 8.6.0,
SQLite 3.53.4, libcurl 8.22.0,
OpenSSL 3.5.9 and nghttp2 1.70.0. The flake supplies the execution closure; the
external Bazel tool repositories declare the closure's files as action inputs.
`MODULE.bazel`, `flake.lock`, `tools/zig-index.json` and the C translation inputs
record source/version custody. Codex's separate upstream graph uses the flake's
`codex-upstream` shell, Bazel 9.0.1 and the pinned upstream Rust 1.95.0 tool graph.
The checked-in validation record declares an isolated overlay for the release
tag's workspace-version/lock mismatch, Bazel metadata reconciliation and test
account/config roots beneath `TEST_TMPDIR`. These validation edits are excluded
from the product patch.

The dedicated upstream shell realized all eleven audited x86_64 Linux fixed-output
tool archives and reported Bazel 9.0.1 through
`nix develop .#codex-upstream --command bazelisk version`. The exact archive
URLs/digests and tool set are recorded in
[upstream tool custody](../../tools/codex-upstream-custody.md). Other platforms,
optional/nightly or DotSlash tools and a complete cold-cache network-free
upstream build remain outside this exercised set.

Proof commands run through `nix develop --command bazelisk ...`. During initial
development, `nix develop path:. --command bazelisk ...` included not-yet-tracked
flake files. Neither Nix dependency realization nor a passing compiler smoke
test proves the daemon, native integrations, installed services or portable
delivery. RBE endpoints and credentials remain operator configuration; no remote
execution or remote cache result is claimed here.

Compilation uses Bazel's local namespace sandbox. The checked-in test strategy
uses `processwrapper-sandbox` with declared inputs/runfiles because namespace UID
remapping obscures owner identity needed by private-file fixtures. These results
do not establish test isolation from accessible host or Nix-store paths.

## Local predicate matrix

Statuses distinguish completed local predicates from unrun platform and product
gates. Imported module cases overlap targets and must not be added into a total.

| Target | Predicate | Recorded status |
| --- | --- | --- |
| `//:toolchain_test` | Compile and execute a Zig 0.17.0 smoke test in the Bazel sandbox. | Passed again in the full-project invocation with the declared runtime. |
| `//:entropy_test` | Exercise secure entropy twice without changing the official Zig SDK. | Passed 1 scenario again in the full-project invocation using the declared GNU 2.42 runtime. |
| `//:domain_test` | Distinct identity/source/grant/resource types; verified enrollment, lifecycle, sticky routes, lease invariants and compatible bucket aggregation. | Latest rerun passed all 32 scenarios, including duplicate scopes, atomic observation batches, repeat-job generations, durable Git recency and native cooldown retirement. |
| `//:envelope_test` | Authenticated ciphertext and account/grant/generation/purpose/scope context isolation. | Passed 2 scenarios. |
| `//:storage_test` | SQLite ciphertext custody, durable generations, writer ownership, rotation/recovery and lost-key behavior. | Passed all 14 Zig scenarios; encrypted fixture custody only. |
| `//:vault_test` | Typed vault outcomes with a fake key backend, including loss/creation/error/race handling. | All 6 Zig scenarios passed again after local-key scrub and the declared GNU 2.42 loader fix. Real vault interaction unrun. |
| `//:vault_bridge_test` | Native bridge rejects invalid root identifiers before OS vault IO and clears output buffers. | Passed negative ABI binary; no real vault interaction. |
| `//:discovery_test`, `//:file_metadata_test` | Explicit fixture acquisition, permissions/no-follow checks, detach recovery, stable reads and normalized metadata. | Passed 38 discovery/imported Zig cases and 2 dedicated metadata cases; copied identity and refresh ownership remain untrusted. |
| `//:transport_test` | Bounded libcurl owner/queues, verified endpoints, cancellation/deadlines and fixture response handling. | Latest focused rerun passed all 15 Zig cases. Loopback HTTP and synthetic provider JSON only. |
| `//:tls_probe` | Compile the unauthenticated transport probe used by delivery relocation checks. | Binary compiled and actual relocated probe rejected untrusted TLS and accepted explicitly trusted local HTTPS. |
| `//:observer_test` | Fixed GitHub/Codex account-read capacity readers with authorization/freshness checks, compatible windows/units and bounded polling. | Latest focused rerun passed all 58 observer/imported Zig cases. Real capacity reads unrun. |
| `//:browser_grant_test` | Browser-bound context, declared scope and lease/path/partition constraints. | Passed, 2 scenarios; no real browser grant import. |
| `//:browser_bridge_test` | Narrow request admission, bounded framing/schema/origin/authority checks and owned escaped-string disposal. | Passed, 10 in-file scenarios; production provider export remains disabled. |
| `//:paths_test` | Private paths, metadata normalization and descriptor/no-follow boundaries. | Passed all 4 Zig scenarios. |
| `//:daemon_test`, `//:engine_test` | Peer-user boundaries, actor persistence and separation of public control from private materialization. | Daemon fixture gate passed; engine's latest rerun passed all 124 imported Zig cases. |
| `//:engine_acceptance_test` | Actor-level synthetic account substitution with stable binding/session identifiers, exact-resource isolation, retry/acceptance fences, private-purpose boundaries, restart and lifecycle custody. | Latest rerun passed all 132 imported scenarios, including 8 actor cases; no native application/live handoff inference. |
| `//:codex_test`, `//:git_test`, `//:claude_test`, `//:catalog_test` | Pure adapter boundaries, reversible settings and honest capability classification. | Passed in the final full-project gate; no live continuity inference. |
| `//:native_probe_test` | Stock native control inspection and truthful unsupported-hook handling. | Passed all 11 Zig scenarios; fixture native sockets only. |
| `//:setup_test` | Descriptor-safe reversible settings transactions, encrypted recovery records, caller deadlines and capability generation fences. | Latest full-project output passed all 26 imported Zig scenarios, including 10 setup cases; real native configuration is unchanged. |
| `//:reference_test`, `//:reference` | Generate CLI, API method/channel summaries, lifecycle, capability and release facts from source definitions. | Passed all 5 imported source test cases and generated the producer output; the latest 15,221-byte bundle was imported by digest into the development SPA and its seven-target gate passed. |
| `//:unit_tests` | Integrated in-file synthetic suite. | Latest rerun passed all 143 imported Zig scenarios; imported cases overlap other targets. |
| `//:format_test` | Check current Zig source formatting with the declared SDK. | Final standalone gate passed after formatting all declared Zig source paths. |
| `//extensions:tests` | Node fixtures plus completeness of built Chromium ZIP and Firefox XPI packages. | Passed 28 scenarios, none failed/skipped; ZIP/XPI produced, browser installation unrun. |
| `//extensions:host_setup_test` | Exact extension authority, trusted executable/path chains and ownership-bound native-host manifest install/remove fixtures. | Passed all 41 Python fixtures, including intermediate alias/path rejection; no actual browser profile registration. |
| `//clients/linux:control` | Compile/link the Qt tray/settings executable with declared native dependencies. | Latest build passed; actual offscreen widget self-check marker/exit 0 passed. Installed desktop/tray/service proof unrun. |
| `//clients/linux:transport_test` | Fixture peer/version/frame/reconnect checks and no automatic mutation replay. | Passed all 4 scenarios in ordinary and ASAN runs after destructor lifetime repair; ASAN leak detection disabled. |
| `//clients/macos:*` | Native SwiftUI application bundle and Apple SDK compilation. | Unrun on this Linux execution platform. |
| `//clients/macos:bundle_test`, `//clients/macos:macho_test` | Linux-capable bundle/plist/version fixtures and Mach-O dependency/signing-tool policy fixtures. | Passed 21 bundle and 46 Mach-O scenarios; does not compile Swift or execute macOS. |
| `//integrations/codex-upstream:patch_test`, `//integrations/codex-upstream:tooling_test` | Offline patch application, exact affected-source hashes and source safety/tooling oracle. | Final 107-file artifact/source oracle passed both targets after schema/overlay regeneration; this oracle does not execute Rust. |
| Codex upstream eight-target production compilation | Compile native core, application server, protocol, configuration, CLI, TUI and schema exporters against the pinned upstream graph. | Final frozen production graph passed all 8 targets in 148.955 seconds; this is compilation, without native-support/live promotion. |
| Codex upstream focused native behavior | Synthetic broker custody, cancellation, admission, auxiliary-auth isolation, metadata and native terminal UI fixtures. | Filtered eight-target gate passed 55 Rust cases; full upstream suites and live application/provider continuity are unrun. |
| Codex upstream additional TUI/configuration predicates | Selected-thread cached status/native fallback and strict broker configuration/schema fixtures. | Named TUI gate passed 3 Rust cases and broker-filtered configuration gate passed 6; these are explicitly scoped subsets. |
| Codex upstream protocol unit target | Broker wire round trips and generated JSON/TypeScript stable/experimental fixture reconciliation. | Final full protocol rerun passed 318 Rust tests; one upstream schema-writer test is intentionally ignored. No provider calls. |
| `//delivery:delivery_test` | Deterministic bundle verification and isolated ownership/install/remove fixtures. | Latest rerun passed all 25 scenarios, including independent Qt runtime-tree ownership/cleanup, obsolete dependency cleanup and rollback; real installation/service activation unrun. |
| `//delivery:cli_test` | Actual Git helper omits passwords from get, forwards rejected passwords only for erase, ignores store and emits redacted adapter-error diagnostics. | Passed 3 actual-binary cases against a private same-user fixture peer; no provider or real daemon custody accessed. |
| `//delivery:portable_test` | Declared ELF/Qt plugin closure discovery, runtime/dependency/launcher checks and public certificate payload bounds using generated fixture binaries. | Latest rerun passed all 31 scenarios, including separated process-library namespaces; fixture tool proof. |
| `//delivery:release_archive`, `//delivery:relocation_test` | Package actual binaries and execute relocated CLI/Qt/native framing and TLS under a restricted environment while checking loader traces for original lookup paths. | Actual x86_64 Linux archive and one comprehensive relocation case passed; host/Nix-store accessibility and desktop-resource limits remain below. |

Completed commands reported by the owning implementation agents:

```sh
nix develop path:. --command bazelisk test //:toolchain_test
nix develop --command bazelisk test //:browser_bridge_test
nix develop path:. --command bazelisk test \
  //clients/linux:transport_test //clients/linux:control
nix develop path:. --command bazelisk test //clients/linux:transport_test \
  --copt=-fsanitize=address --linkopt=-fsanitize=address --copt=-g \
  --strip=never --test_env=ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
  --test_output=all
```

The browser bridge gate passed all 10 scenarios. Its first execution failed a
test assertion that inspected allocator-poisoned memory after free; the corrected
test observes explicit sensitive-buffer erasure before release. The rerun passed.

The later explicit browser native-host setup gate passed all 41 Python fixtures
at invocation `0efcf18e-2d08-4cb3-9fb3-17d3454a6d1e`. It checks exact extension
authority, preview without writes, owned mode-0600 install/remove and idempotence,
no overwrite, tamper preservation, bounded FIFO handling, intermediate alias and
directory custody and rejection of symlink-target parent traversal. All mutations
use private fixture directories; no actual browser profile was registered.

```sh
nix develop --command bazelisk test //extensions:host_setup_test
```

The Linux client later repeated all four transport cases and compiled the latest
control executable at invocation `27d40df9-bdda-4871-9b41-ee0b7e451bbe`. Its
actual offscreen `--self-check` constructed the Qt widgets, emitted
`OMUX_CONTROL_SELF_CHECK_OK` and exited 0 at invocation
`be1257ab-189d-498e-b538-483800875681`. This does not establish installed tray or
service behavior; the earlier ASAN run is a separate transport checkpoint.

```sh
nix develop path:. --command bazelisk test \
  //clients/linux:transport_test //clients/linux:control --test_output=all
nix develop path:. --command bazelisk run //clients/linux:control -- --self-check
```

The client owner supplied no extra environment/platform/sanitizer flags for
these commands. The application's self-check selects offscreen Qt when the
platform variable is unset; this is a real widget execution without a desktop
session.

The central batch below did not pass as a whole while C translation/linking was
being repaired. Its independently completed outputs established the 21-scenario
domain checkpoint, both envelope and browser-grant scenarios, and the native
vault bridge's negative ABI checks. Storage, vault and transport must be recorded
from their subsequent completed execution.

```sh
nix develop --command bazelisk test //:storage_test //:vault_test \
  //:transport_test //:envelope_test //:domain_test //:browser_bridge_test \
  //:browser_grant_test //:vault_bridge_test --jobs=4
nix develop --command bazelisk test \
  //extensions:tests //delivery:delivery_test --jobs=4
```

The second batch passed all 28 extension scenarios and produced the extension
archives; its delivery predicates initially failed and remain separately tracked.

```sh
nix develop --command bazelisk test //:transport_test //:observer_test \
  //:browser_grant_test //:tls_probe --jobs=4 --test_output=errors
```

This focused batch passed transport's 12 cases, browser-grant's two cases, and
compiled the probe. The observer allocation-failure case initially crashed;
the repaired coordinator passed the completed rerun below. These transport
fixtures use loopback HTTP, not authenticated provider or real TLS traffic.

```sh
nix develop --command bazelisk test //:observer_test --jobs=2 --test_output=errors
```

All 47 observer/imported cases passed, including the allocation-failure scenario
after fixing partially initialized optional ownership. The gate also exercised
the later transport CA-path validation case. It uses synthetic quota responses;
it does not establish real account quota extraction or a provider refresh writer.

The subsequent focused batch used the same four-target command and passed at
invocation `c25421ef-59d9-47b8-842e-1f5b6a451634`: transport 15, observer 57
and browser grant two; the TLS probe compiled. Imported scenarios overlap and
must not be added into a total. Codex parser/observer cases exercise allowed
status independently from percentages, exact feature/window isolation, absent
or malformed usage preservation, identity mismatch, bounded polling and atomic
multi-window allocation failure. Provider buckets with unknown identity remain
non-additive. These synthetic response/loopback tests make no authenticated
provider, renewal or revocation calls.

The next observer-only rerun passed 58 cases at reported invocation prefix
`9f814089`, after changing GitHub bucket identity from a raw provider subject to
the opaque deduplicated account handle. Repeated grants still share one bucket;
the privacy predicate rejects raw numeric subject disclosure.

```sh
nix develop --command bazelisk test //:observer_test --jobs=4 --test_output=errors
```

The build owner reported this active batch and its completed entropy predicate:

```sh
nix develop --command bazelisk test //:storage_test //:entropy_test \
  //:unit_tests //:omux //:omuxd --keep_going --jobs=4
```

Invocation `ef305de6-8a4d-4854-9878-70cde368f647` passed the entropy test. The
remaining batch targets were still running at that checkpoint; the invocation
must not be reported as an overall success until completed output establishes it.

The next core batch completed storage's 14 cases, native probe's 11, settings
setup's 25, discovery's 38 and dedicated file metadata's two. Paths reused its
successful four-case output. The batch did not pass as a whole: aggregate tests,
CLI/daemon execution and reference generation encountered a host-loader/libc
mismatch, subsequently addressed by declaring the matching runtime loader.

```sh
nix develop --command bazelisk test //:storage_test //:unit_tests //:omux \
  //:omuxd //:native_probe_test //:setup_test //:paths_test \
  //:file_metadata_test //:discovery_test //:reference --keep_going --jobs=4
nix develop --command bazelisk test \
  //clients/macos:bundle_test //clients/macos:macho_test --jobs=4
```

The core batch is invocation `c3929eeb-a8ec-46e0-96fd-4b8028776471`. The macOS
tooling fixture batch is invocation `c519c49f-b1a0-4d4e-a797-6ba22672131e`, with
21 bundle and 46 Mach-O tests passing. These Linux fixture predicates establish
neither Darwin SDK compilation nor installed macOS behavior.
Domain's subsequent completed 31-case rerun is invocation
`b66b8ee6-1f56-4a06-9b67-b1914be24616`.

```sh
nix develop --command bazelisk test //:domain_test
```

Its next rerun passed all 32 at invocation
`444e4fb1-e541-4fc0-ae2b-ea5c837409ee`, including retirement of expired native
unavailability while preserving active cooldowns and the latest stale provider
sample.

The first complete project invocation, `3f0f87c2-6781-48bf-bb25-3adfb47fd652`,
used the command below but did not pass: 30 test targets passed, five failed and
one failed to build. It exposed a temporary fixture permission change through an
`O_PATH` handle, formatting drift, pending Codex artifact reconciliation, a Qt
package declaration mismatch and unintended `.direnv` legacy-package traversal.
The graph now excludes generated local state; fixture permissions use
descriptor-relative `fchmodat` without weakening production private-root checks.
This full invocation's settings setup output passed 26 imported cases, including
10 setup-specific predicates and the caller-deadline regression.

```sh
nix develop --command bazelisk test //... --keep_going --jobs=4
nix develop --command bazelisk test \
  //:unit_tests //:engine_acceptance_test //:format_test --keep_going --jobs=4
```

The focused repetition at invocation `e56a2330-70c5-4262-9822-b264a422a8c1`
passed all 143 integrated and 132 acceptance cases. Format failed separately in
that invocation; the final standalone gate below passed at invocation
`08446652-6fac-4158-8e20-a4bc73c7b2cf`. Acceptance includes eight actor predicates, with imported
coverage overlapping the integrated and module suites; their counts must not be
added together. The fixture cases establish route/resource isolation, one
different-account preacceptance alternate with the same session identifier,
accepted-stream replay fencing, capability/channel/purpose checks, encrypted
restart and old-handle invalidation, independent source custody and global
forget tombstones, drain completion, password-correlated Git rejection, expired
queued mutation and latest-native-handle detachment. None observe real Codex
launch/resume, a provider account or same-process live continuity.

```sh
nix develop --command bazelisk run //tools:format -- \
  src/*.zig src/integrations/*.zig src/platform/*.zig tools/*.zig
nix develop --command bazelisk test //:format_test --test_output=errors
```

The formatter invocation was `c4b972cc-148d-4451-9c06-1afa2faecf03`; it made
formatting changes only. Engine's current 124-case gate passed earlier at
invocation `2fb38e86-0900-4cb7-aa39-6e32ef9a1499`, within the partial command
below. The command also built the reference producer, CLI and daemon; other
targets at that point still exposed the fixture/formatting corrections described
above and the command was not an overall success.

```sh
nix develop --command bazelisk test //:unit_tests //:engine_test \
  //:engine_acceptance_test //:format_test //:reference //:omux //:omuxd \
  --keep_going --jobs=4
```

After the runtime, native artifact and browser setup froze, the complete project
gate passed at invocation `b7e9ac46-2b86-42ee-bb39-969c022e3c2e` in
110.054 seconds: 37 of 37 test targets passed, none failed or skipped.
Seven tests executed and thirty reused valid cached outputs; 66 top-level
targets were analyzed. This supersedes the earlier partial full invocation's
failures without erasing their record. It does not execute the macOS SDK or
turn synthetic predicates into live provider/continuity evidence.

```sh
nix develop --command bazelisk test //... --keep_going --jobs=4
```

The final required build also passed all 66 targets at invocation
`d877a635-0adf-4186-b898-8f6d62e62261`, in 9.773 seconds, with no failures.

```sh
nix develop --command bazelisk build //... --jobs=4
```

The delivery and Codex owners reported these completed checkpoint commands:

```sh
nix develop path:. --command bazelisk test //delivery:delivery_test
nix develop --command bazelisk test //delivery:portable_test
nix develop --command bazelisk test \
  //integrations/codex-upstream:patch_test //integrations/codex-upstream:tooling_test
```

The 20-case delivery checkpoint is invocation
`cfaff1ba-7c32-4380-b621-086fccd44ebf`. Portable tooling passed all 17 fixture
scenarios; its reported invocation prefix is `7dbab9c6`. Codex artifact/tooling
proof is invocation `7fe8f423-f043-4eb2-b4f8-01f97965a4f5`, with both Bazel
targets passing. Later installer edits and generated-schema reconciliation require
the relevant completed gates again; these checkpoints do not attest changed
inputs.

The delivery command subsequently passed all 22 cases at invocation
`8f56a352-fa31-4c10-9274-815c8022da73`, covering owned obsolete-library cleanup,
modified-file rejection and rollback restoration after the installer edits.
Its next rerun passed all 25 at invocation
`68e1c034-6fbe-4bea-9a58-1d412f20043a`, adding ownership checks for optional Qt
executables/configuration/plugins and malformed delivery records. Actual Qt
runtime relocation remains a separate gate.
Portable tooling subsequently passed all 21 cases at reported invocation prefix
`597217cf`, including optional Qt/plugin dependency closure and payload escape
rejection. After splitting the CLI and Qt process-library namespaces, ownership
again passed 25 cases at invocation `7031c9dc-3c94-438e-a579-4a894aa61e8d`
and portable tooling passed 29 at reported invocation prefix `d0d1ed61`.
Its latest rerun passed 31 at reported invocation prefix `7c253126`.
Their exact latest commands follow.

```sh
nix develop --command bazelisk test //delivery:delivery_test --test_output=errors
nix develop --command bazelisk test //delivery:portable_test
```

The actual archive/relocation gate passed one comprehensive case in 9.9 seconds
at invocation `02c4ed8f-92bb-4665-9966-cab22dbd76a7`. It installed the built
archive into a fresh path with spaces, checked CLI/daemon/compatibility aliases
with `--version` and the Git alias's scoped fallback, started genuine Qt
offscreen widgets through the packaged plugin,
checked reference output through a pipe and regular file, rejected untrusted
TLS before accepting explicitly trusted local HTTPS through the real transport
probe, exchanged two structured native-host error frames while stdin remained
open, and removed
only owned installation files. It accessed no provider or real account/vault.
Observed loader traces contained no Nix-store runtime lookup; the original store
remained accessible, and host fonts/XKB and the fixed OS service-manager interface
remain dependencies. This is a local relocated execution predicate, not a
clean-machine or interactive X11/Wayland compatibility proof.

```sh
nix develop --command bazelisk test //delivery:relocation_test --test_output=errors
nix develop --command bazelisk run //delivery:verify -- \
  --verify "$PWD/bazel-bin/delivery/release_archive.tar.gz"
```

The verifier at invocation `b7cce0b7-c76c-480b-aa91-78a72619c8e7` reported
138 manifested artifacts and 59,466,590 archive bytes, SHA256
`5b75e2da5c5e9c0b17aa682d792f2448edf51933615d11a0f185b7eab3acdddc`.
The manifest identifies `portable-linux`, `x86_64-linux`, experimental
`0.2.0-dev`, `unversioned-development-source` and `sourceDirty: true`.
This receipt describes an unstamped local development archive, not a publication.

The native source checkpoint passed eight targets at invocation
`f0f7ee16-6591-4efc-a114-41d0c8367435`, in 430.029 seconds. These commands
ran from `/tmp/omux-codex-upstream-v0157` using the project flake and the
upstream action graph. The first is a checkpoint before final ancillary-auth
and selected-thread UI changes. The second is the latest unchanged-protocol
repetition at invocation `c6b9ce00-fc17-43c9-b791-dd249b8cdcdf`, with the
declared Nix test PATH; 318 passed and one was intentionally ignored.

```sh
nix develop /srv/fast-local/jess/git/oauth-mux#codex-upstream --command \
  bazelisk --output_user_root=/srv/fast-local/jess/state/codex/omux-codex-bazel-proof \
  build --jobs=4 --strategy=sandboxed --lockfile_mode=error \
  //codex-rs/core:core //codex-rs/app-server:app-server \
  //codex-rs/config:config //codex-rs/app-server-protocol:app-server-protocol \
  //codex-rs/tui:tui //codex-rs/cli:codex \
  //codex-rs/config-schema:codex-write-config-schema //bazel/schema:public-schema-bundle
nix develop /srv/fast-local/jess/git/oauth-mux#codex-upstream --command bash -c \
  'exec bazelisk --output_user_root=/srv/fast-local/jess/state/codex/omux-codex-bazel-proof test --jobs=4 --lockfile_mode=error --test_env=PATH="$OMUX_CODEX_TEST_PATH" --test_output=errors //codex-rs/app-server-protocol:app-server-protocol-unit-tests'
```

The earlier protocol checkpoint `fa360dbd-a900-456f-a271-c5f9b9bcdc57`
passed the same 318 tests with upstream's host test PATH. The later command
records the flake-supplied tool path explicitly. Neither run establishes
ordinary application launch/resume or live account continuity.

The final frozen native production graph passed at invocation
`a3bfa1d2-cbdc-4499-8384-845c9d276a54`: eight targets, nine actions,
148.955 seconds. It includes auxiliary-auth ownership fences, portable idle
detachment, cached route metadata and the selected-thread terminal account UI.
The exact command ran in the same upstream checkout with the Nix-contained
Rust 1.95.0/LLVM 22.1.8 tool set:

```sh
nix develop /srv/fast-local/jess/git/oauth-mux#codex-upstream --command \
  bazelisk --output_user_root=/srv/fast-local/jess/state/codex/omux-codex-bazel-proof \
  build --keep_going --jobs=4 --strategy=sandboxed --lockfile_mode=error \
  //codex-rs/core:core //codex-rs/app-server:app-server \
  //codex-rs/config:config //codex-rs/app-server-protocol:app-server-protocol \
  //codex-rs/tui:tui //codex-rs/cli:codex \
  //codex-rs/config-schema:codex-write-config-schema //bazel/schema:public-schema-bundle
```

The final filtered synthetic behavior gate passed at invocation
`167ec256-6706-4c7f-af4b-597c352b12b7`, in 235.989 seconds. It executed
55 Rust cases across eight targets: core 25, analytics 2, application server 5,
models manager 4, TUI 13, memory write 3, core plugins 2 and CLI login 1.
The filter selects the broker predicates; this does not claim the full upstream
test suites. Test-owned roots and generated fixture credentials isolate private
Unix-socket wire, cancellation/lease cleanup, capability symlink/FIFO rejection,
ambient-auth draining, portable detachment, metadata/UI and ancillary ownership
fences from real personal account/configuration stores.

```sh
nix develop /srv/fast-local/jess/git/oauth-mux#codex-upstream --command \
  bazelisk --output_user_root=/srv/fast-local/jess/state/codex/omux-codex-bazel-proof \
  test --keep_going --jobs=4 --strategy=sandboxed --lockfile_mode=error \
  --test_output=all --test_filter=broker --test_arg=broker \
  --test_arg=--test-threads=1 --test_sharding_strategy=disabled \
  //codex-rs/core:core-unit-tests //codex-rs/analytics:analytics-unit-tests \
  //codex-rs/app-server:app-server-unit-tests \
  //codex-rs/models-manager:models-manager-unit-tests //codex-rs/tui:tui-unit-tests \
  //codex-rs/memories/write:write-unit-tests \
  //codex-rs/core-plugins:core-plugins-unit-tests //codex-rs/cli:cli-login-test
```

After regeneration, the exact 107-file artifact/source oracle passed both project
targets at invocation `684c6dd1-d611-401b-a0c5-d068270fe930` using the previously
recorded `patch_test`/`tooling_test` command. The source manifest binds the native
configuration schema and both compressed protocol overlays as well as every
affected source. That offline check establishes exact application/hashes; it
does not substitute for the separate Rust executions.

Final named terminal-account predicates passed 3 cases at invocation
`805f41f9-8719-417d-9480-7c6acace260e`; strict broker configuration/schema
predicates passed 6 at `1d88ba0f-e72f-4d84-b5ef-8ce5f49af44c`. The complete
protocol target passed 318 at `487e534d-a719-4db8-9f32-87250ee2e5c1` in
29.626 seconds, with one intentionally ignored upstream schema-writer helper.
The final exported config schema is SHA256
`3baa23e800e13869f1f67273268aa9e280e2a650c569bc193aca7c35ffdcd5f5`, produced
at `4678f4be-c3dc-4b04-8a95-e681db0e43f4`. Repeating the same eight-target
production command against the final exported source passed at
`a1ce8983-f18d-4e35-8505-56c22436c513`, in 10.111 seconds using valid cached
production actions.

```sh
nix develop /srv/fast-local/jess/git/oauth-mux#codex-upstream --command \
  bazelisk --output_user_root=/srv/fast-local/jess/state/codex/omux-codex-bazel-proof \
  test --jobs=4 --strategy=sandboxed --lockfile_mode=error --test_output=all \
  --test_arg=loaded_status_checks_thread_custody_before_rendering_native_account \
  --test_arg=bound_thread_retains_cached_route_across_global_native_account_notifications \
  --test_arg=status_command_renders_immediately_and_refreshes_rate_limits_for_chatgpt_auth \
  --test_arg=--test-threads=1 --test_sharding_strategy=disabled \
  //codex-rs/tui:tui-unit-tests
nix develop /srv/fast-local/jess/git/oauth-mux#codex-upstream --command \
  bazelisk --output_user_root=/srv/fast-local/jess/state/codex/omux-codex-bazel-proof \
  test --jobs=4 --strategy=sandboxed --lockfile_mode=error --test_output=all \
  --test_filter=broker --test_arg=broker --test_arg=--test-threads=1 \
  --test_sharding_strategy=disabled //codex-rs/config:config-unit-tests
nix develop /srv/fast-local/jess/git/oauth-mux#codex-upstream --command \
  bazelisk --output_user_root=/srv/fast-local/jess/state/codex/omux-codex-bazel-proof \
  test --jobs=4 --strategy=sandboxed --lockfile_mode=error --test_output=errors \
  --test_arg=--test-threads=1 --test_sharding_strategy=disabled \
  //codex-rs/app-server-protocol:app-server-protocol-unit-tests
nix develop /srv/fast-local/jess/git/oauth-mux#codex-upstream --command \
  bazelisk --output_user_root=/srv/fast-local/jess/state/codex/omux-codex-bazel-proof \
  run --jobs=4 --lockfile_mode=error //codex-rs/config-schema:codex-write-config-schema \
  -- --out /tmp/omux-codex-upstream-v0157/codex-rs/core/config.schema.json
```

The final [native validation record](../../integrations/codex-upstream/validation.json)
is SHA256 `25fd1a7604d24ef30e858dc76bddafe7d56d52c4d1ada0325235842f14af527f`.
Its [107-file source manifest](../../integrations/codex-upstream/manifest.json)
binds patch SHA256
`450e7515209a5a1efd5b239e0e868b06f0e79ce883bdb2616a3afa106f478360`,
base SHA256 `a3b5e866401a055ae55a4cb64e3feb6a7ff414dae7150bdc9fab70a8d26dd494`
and binary-overlay SHA256
`be1a71b46dae300e3e4497d2bed3fc82a3efb2b0e954b31527df7c4bd2e08f7e`.
These are exact candidate/source receipts; `native_support` remains false.

## Runtime boundary and unrun product gates

The daemon, control protocol, encrypted store, OS vault bridges and network actor
are new implementations. Public clients receive redacted metadata; credentials
are confined to private acquisition/materialization channels. Unit and fixture
coverage can establish these local predicates without accessing real account
directories, reading real vault secrets or spending provider calls.

The acquisition path requests independent provider identity before retaining an
externally owned access credential. Safe native file acquisition and fixed
GitHub/Codex account-read operations are implemented; their local fixture gates
and real provider evaluation remain separate. Private manual API-key import has
a 30-day custody default; manual OAuth and copied native credentials default to
one hour. Explicit manual custody is bounded from one second to 30 days and never
extends a known provider expiry. Explicit verified re-enrollment can clear a
tombstone; periodic source reconciliation cannot authorize that decision.
Copied native account hints cannot activate authorization or transfer refresh
ownership. Refresh adoption, renewal ownership transfer and upstream revocation
require completed implementation and version-bound evaluation. Repair reconciles
already authorized sources and reports actual queued verification, retained
readiness or a required provider authorization action. A job
that reports `needs_user` does not establish a completed enrollment/repair flow.
Warm-route policy metadata alone does not prove preauthentication or warming.

Git HTTPS uses its native credential helper with independently verified GitHub
usernames. Repository contexts and route handles are opaque hashes in public
metadata. Erase requires the rejected password to match current private custody
using a constant-time digest comparison; missing or stale password reports are
no-ops. A matching rejection creates a 60-second account/repository cooldown,
without revoking the account or invalidating other repository authorization.
Idle Git routes form a bounded cache: at the 960-binding threshold the least
recently used idle Git contexts retire by durable revision, preserving the
current route, native bindings and in-flight leases. This reserves space for 64
native bindings where retirement is possible. Cache eviction does not change
grants; unchanged compatible contexts stay sticky while retained.

Chromium/Firefox transport and packaging are implemented. Production Codex,
Claude and GitHub browser cookie/storage export remains blocked pending exact
provider schema and identity proof. The fixture adapter is confined to explicit
test mode. Declared provider permissions, an extension package or successful
framing never establish reusable production browser authorization. No automated
browser is part of the product and no live browser profile was imported.
The explicit native-host registration tool emits reviewable narrow Chromium or
Firefox manifests and uses per-user ownership receipts for installation/removal.
It rejects directory symlinks, unsafe executable hops and alias targets with
parent traversal; it does not activate production exports. Live browser discovery
and installation remain separate gates.

The Codex candidate targets official `rust-v0.157.0`, commit
`00c972ed5d6ff6499317fd41b7f23605b8e6850d`; its annotated tag object is
`ac21625ddf7f9dd5f34b2802212cf20295fdff95`. It adds optional native per-thread
registration and request-owned authorization. Omux does not ship a fork and
stock Codex has no implied support for these methods. The offline patch oracle
does not establish Rust execution. The separate eight-target compilation and
protocol fixture gates above establish their stated predicates. Final
ancillary-auth/UI compilation, the filtered 55-case behavior gate and exact
107-file source oracle passed; final named UI, configuration and protocol fixture
repetition also passed as recorded above. Ordinary
launch, existing-process attachment, resume, account-status behavior against
real providers and same-process handoff require their own exact application and
source provenance; none are claimed here.
Account-bound opaque reasoning, uploaded-file and compaction state can prevent
safe attachment or account substitution. Adoption leaves shared model discovery
in descriptive mode and remote plugins in local-only mode until process exit,
including unbound threads in that process. Unsupported ancillary authorization
fails closed. A cancelled native Apps subscription retains an authorization
fence until process exit because its SDK lacks a terminal acknowledgment; late
attachment can remain unavailable. These limits require live compatibility
evaluation before support promotion.

The Linux Qt client and macOS SwiftUI menu-bar client are thin controls. Native
macOS compilation, Keychain interaction, service registration/approval and an
installed menu-bar session require a macOS execution platform. A Linux source
review does not satisfy them. Fixture transport success does not establish an
installed daemon or desktop-session launch.

The Linux development archive packages its declared ELF closure, loaders, Qt
plugins and public CA bundle. CLI and Qt have independent runtime-library trees,
preserving their declared libcurl versions. A generated native offscreen-startup
witness binds Qt's systemd-library selection and conflicting candidates by digest;
the archive binds the patched artifacts as well. The executed relocation gate
above covers that local archive with the stated host-resource limits. A bundle
without the declared Linux runtime inputs identifies itself as
`development-nix-closure-required`.
Signing, clean stamped release provenance, real installation, service activation
and website publication remain separate unrun gates. The current source-generated
15,221-byte reference bundle was imported by digest into the separate development
SPA, with SHA256 `f16dabca84e7dc14ea3bd1746cdb05d9de2a27703479c3936a2a2b8532a246af`.
Its latest seven-target gate passed at invocation
`65ca19d4-bb76-4f2a-96ac-ca053d43cce8`: nine schema/import unit cases, zero
Svelte errors/warnings, build/archive/format checks and two Playwright route
cases at 375×812 and 1280×900 viewports. This proves local development rendering
against those imported bytes, not deployment or runtime capability support.
The producer emits the API method/channel/summary catalog and CLI, lifecycle,
capability and release metadata. It does not derive complete per-method parameter
JSON schemas from handler types.

The exact command below ran from `/srv/fast-local/jess/git/omux.xoxd.ai`.
`//:check` expands the unit, Svelte and reference checks; all seven test targets
passed, none skipped. Archive checks compared the packaged HTML/documentation
and public JSON against the imported bundle. The browser cases covered the
home, reference/API and direct-agent routes at both viewport sizes.

```sh
nix develop --command bazelisk test //:check //:archive_check //:format_check \
  //:playwright_chromium_smoke //:playwright_local_route_smoke
```

No live successor continuity claim is available until ordinary launch, native
resume, accepted-stream fencing, account substitution in the same application
process, and preserved native history/session/tool state pass against an exact
application build. Historical wrapper, relaunch and route-warming proofs do not
satisfy this gate.

## Review findings and reconciliation

These checkboxes record source review only. A checked item does not replace the
corresponding executable gate. Unchecked items remain open until the actual fix
is reviewed; they must not disappear merely because a target passes.

- [x] Failure reconciliation restores durable domain, settings, descriptions,
  revision, policy and capability epochs; auxiliary lease/import ownership is
  allocated before commit and retained or cleaned up according to commit state.
  A storage ambiguity fences further credential service.
- [x] Lease expiry is processed by periodic actor work; terminal history expires
  and accepted requests can report cleanup beyond access-lease expiry. Hung
  accepted records have a separate bounded cleanup horizon.
- [x] Native binding lifetime has an explicit idle release path, Git-only idle
  contexts retire by durable recency, and repeat source work reopens one durable
  operation row with a new generation. Fixed-size limits still bound overload.
- [x] Expired native rejection history retires even when each rejected resource
  is unique; current cooldowns and latest stale provider samples remain retained.
- [x] Binding identity is namespaced by application/session/external binding.
- [x] Opaque source, operation and lease identifiers serialize as JSON strings.
- [x] Capacity grouping includes issuer and compares resources by value.
- [x] Leases retain audience/scopes/resource and end by source authorization
  expiry in addition to provider/custody expiry.
- [x] Owned parsed request/decrypted strings are wiped before normal disposal
  and post-parse validation failure.
- [x] Native rejection reports use immutable lease grant/generation; 401 is
  generation-specific, 403/429 creates a resource cooldown, and a safe alternate
  excludes the rejected account identity. Unknown capacity remains eligible;
  explicit fresh unavailability blocks that resource.
- [x] Git-context rejection records a bounded account/repository cooldown without
  invalidating unrelated grant capability; ordinary username-free acquisition
  can be rejected using the returned verified username and matching password.
  Incomplete/stale password reports cannot cool a newer credential generation.
- [x] Materialization checks request purpose/audience,
  source authorization, held expiry and the ready grant generation before decrypting.
- [x] Browser disconnection removes retained ciphertext and returns structured
  operational errors.
- [x] Native-host registration validates every binary symlink hop and its
  directory chain, so another user cannot retarget an unchecked intermediate
  alias even when the initial alias and final executable are safe. It rejects
  symlink-target `..` components before normalization to preserve kernel path
  semantics; final executable fixture repetition is recorded separately.
- [x] Enrollment capability publication links a complete fsynced private inode
  without replacing an existing final capability; validated private scratch
  recovery handles interrupted publication. This is source review, without a
  direct crash-injection gate.
- [x] Git install/remove is descriptor-safe, atomic, durable and recoverable;
  integration directories are private, capability revocation survives reinstall,
  and a failed settings write cannot masquerade as completed installation.
  Noncooperating native configuration editors can still race the final
  comparison/rename; that broader compare-and-swap guarantee remains unproved.
- [x] Git username filtering selects a compatible account instead of rejecting
  a previously selected incompatible username.
- [x] Private Git contexts share the native helper's path validation and return
  `NoEligibleAccount` for native helper fallback when no compatible account remains.
- [x] Repair visits authorized account sources and reports actual verification
  operations or retained readiness, without creating an inert pending job.
- [x] Provider identity parsing uses the bounded typed provider contract and
  redacted fallback labels.

These receipts bind the completed commands, stated predicates and candidate
artifact digests. The remaining gates require their own version-bound evidence;
historical release proof and these local fixtures do not satisfy them.
