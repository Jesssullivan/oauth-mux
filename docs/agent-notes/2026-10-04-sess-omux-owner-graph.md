---
title: Omux native owner candidate graph review
date: 2026-10-04
status: active
summary: Graph review and a new bounded pristine-original exporter support isolated durable candidate staging; execution, graph wiring and candidate artifacts remain with root.
refs:
  - R-N13
  - R-N11
  - R-N12
  - ../plans/omux-native-owner-custody-next-stage-2026-10-04.md
  - ../../integrations/codex-upstream/README.md
  - ../../integrations/codex-upstream/validation.json
  - ../../tools/codex-upstream-custody.md
---

R-N13 authorizes this assigned durable review note. Root is the sole Bazel
operator, generator operator and shared graph/manifest writer. This workstream
inspected source only; it did not execute a build, test, generator, candidate,
host transport, provider request or tracker operation. R-N11 forbids signaling
other processes. An actual managed guard-hook refusal invokes R-N12; no such
refusal occurred during this inspection. PZM remains held, with no service,
GC, remote execution or host readiness claim.

## Preserved candidate and new staging boundary

The existing source authority is official commit
`00c972ed5d6ff6499317fd41b7f23605b8e6850d`. Preserve
`/srv/fast-local/jess/state/codex/omux-codex-source-00c972ed/source`, its private
phase receipts, the existing product patch and packaged originals/binary overlay,
and their recorded failed and successful proof epochs. Its current patch is
`4a236da5663485458744375f8844898682d4b9f160fd37c00e912fd7cd2e76c3`;
the prepared inventory receipt records 8,515 files and digest
`d1516b7ca018277407de37b1af8463ae002e67cab7ac6664ecdbfe6fef9034a3`.
These are retained recorded facts, not a new inventory measurement.

The existing `//integrations/codex-upstream:restore_source` target declares its
Python implementation, patch parser, current manifest/validation/overlays,
coordinator Git and CA bundle. Its four phases take an explicit canonical
durable private root. Fetch creates a new root exclusively; verify compares
all original tracked bytes, modes and safe symlinks against pinned Git. Prepare
first requires an original tree, applies the exact candidate and separately
hashed three-file validation overlay, and checks graph hashes and the complete
prepared inventory. It cannot re-prepare the preserved already prepared tree.
Even verification emits a new exclusive private receipt; it is not a
filesystem read-only executable.

Proposed staging uses separate new sibling roots, selected and created only by
root through the declared tooling: an editable development epoch such as
`/srv/fast-local/jess/state/codex/omux-codex-owner-dev-20261004`, then a final
reproduction epoch such as
`/srv/fast-local/jess/state/codex/omux-codex-owner-final-20261004`. Both retain
their own receipts. Fetch, verify and prepare the development root with the
existing candidate before its assigned Rust owner edits only that new source.
Freeze edits and generated fixture imports before packaging a new candidate
under a separate artifact destination. Restore the final root from pinned Git
using that new artifact, then verify it before and after compilation. Never
change the preserved tree merely to make its historical verifier accept a new
patch. An edited development tree must not retain a passing old inventory
claim.

Two concrete wiring prerequisites remain for root and the assigned custody
tool owner:

- `refresh_artifact` consumes an original tar and explicit new paths. The
  current affected-file base supplies originals only for its own files.
  Newly changed existing upstream paths require their pinned original blobs.
  Export a reviewed regular-file subset from verified pinned Git through a
  declared generator: LICENSE, NOTICE, all previously affected originals and
  every newly affected existing `codex-rs/` file. Keep the current new-file set
  explicit, adding any new source/generated paths. Do not use the edited tree
  as original authority. The parser accepts only LICENSE/NOTICE and canonical
  `codex-rs/` members, with a 64 MiB raw archive bound; the full 84 MiB source
  tree is not a valid replacement tar. File deletion/renaming is not supported
  by the current packaging grammar.
- The existing restoration and patch-oracle targets hardwire the canonical
  artifact data set. A new separately declared artifact target/data set is
  needed for final reproduction and patch checks without replacing the
  original files. Passing an arbitrary directory as a manual argument does
  not establish declared artifact input provenance. Preserve product patch
  and validation-overlay separation, including module/Cargo lock identities.

Manual `bazel run` tool execution has receipts rather than a cacheable declared
artifact action. Its explicit external source/tar inputs and resulting digests
must be recorded. Root may instead wire a cacheable generation action with
explicit files; no declaration-only change proves candidate correctness.

## Proposed commands, not execution receipts

Run the restoration tool from the Omux repository through the default locked
flake shell. Each phase needs its own root-assigned invocation UUID and durable
output root. For example, with root-selected literal values:

```sh
nix develop --ignore-environment --keep HOME --command bazelisk \
  --nosystem_rc --nohome_rc \
  --output_user_root=/srv/fast-local/jess/state/codex/omux-owner-coordinator-proof \
  run --invocation_id="$OMUX_PHASE_INVOCATION_ID" --jobs=4 \
  //integrations/codex-upstream:restore_source -- \
  --root /srv/fast-local/jess/state/codex/omux-codex-owner-dev-20261004 \
  --phase fetch
```

Repeat with phases `verify` and `prepare`, each with a distinct UUID. These
commands are proposed recipes only. No UUID or execution receipt was created
by this review. New artifact declaration/export modes need review and their own
focused meaningful custody tests before their future use.

Run upstream checks from the new candidate source, using the locked
`#codex-upstream` shell, its supplemental rc, `--nosystem_rc --nohome_rc`,
`--jobs=4 --strategy=sandboxed --lockfile_mode=error`, an explicit invocation
UUID and a durable new output root. The shell provides Bazel 9.0.1 and eleven
audited official archive inputs, including Rust 1.95.0 and LLVM 22.1.8. Its
test PATH is the fixed Nix helper closure; retain the recorded test-root
validation overlay. Do not select CI, BuildBuddy or remote configurations.

The exact eight production labels are:

```text
//codex-rs/core:core
//codex-rs/app-server:app-server
//codex-rs/config:config
//codex-rs/app-server-protocol:app-server-protocol
//codex-rs/tui:tui
//codex-rs/cli:codex
//codex-rs/config-schema:codex-write-config-schema
//bazel/schema:public-schema-bundle
```

The config schema executable accepts `--out` for a new source's
`codex-rs/core/config.schema.json`, invoked by upstream `bazel run`.
Protocol changes also require
`//codex-rs/app-server-protocol:app-server-protocol-unit-tests`, including
JSON/TypeScript and stable/experimental embedded-export reconciliation.
Behavior filters must be passed as explicit libtest arguments because the
upstream wrapper's argument precedence differs from Bazel filtering. Record
actual selected counts and intentionally ignored writer helpers separately.
No historical 17/55/318 test count is inherited by the new candidate.

## Schema generation and import

The pinned `bazel/rules/schema_bundle.bzl` produces
`public-schema-bundle.stable`, `public-schema-bundle.experimental` and the
declared `public-schema-bundle.zstd` executable. Each PublicSchema action runs
the declared protocol Rust test executable with exact arguments
`--exact --ignored schema_fixtures_tests::write_schema_fixtures_from_env`.
Its environment declares the output root, experimental mode and stack bound.
The generator executable/runfiles and zstd are explicit tools. Stable output
contains JSON/TypeScript and its precomputed export; experimental output
contains its precomputed export. The native Rust writer serializes the three
export maps and compresses at zstd level 19. This is already a native exporter,
not a schema reconstructed from prose or fixture stubs.

Any normalization or import into the editable source needs a declared bounded
tool with the two generated directory inputs and explicit source destinations.
The existing graph exposes the compressor but does not declare that import
operation. Preserve reviewed normalization semantics and validate every
resulting fixture through the protocol suite. Compile again after import and
package precisely those final bytes. Config/protocol/source inventory receipts
must name the new epoch independently from schema generation and compilation.

## OS bridge and runtime input closure

Current `:native_api` declares `src/platform/vault_bridge.c`, its header and
`//tools:native.h`, SQLite/curl, Linux libsecret and Darwin Security and
CoreFoundation frameworks. The selected C/C++ toolchain declares its immutable
headers/tools and fixed manifest coreutils executable search directory. Zig
uses the patched rules_zig 0.17 translation path, declared standalone
translate-c/runtime modules, C compilation-context headers and the selected Zig
library. `tools/runtime_zig.bzl` adds selected root loader/SDK flags and Darwin
SDK inputs; no ambient SDK or compiler search is authorized.

A new OS-C owner bridge requires explicit `.c` source and `.h` declarations
in the shared native library, including its header in the translation surface
if Zig imports its ABI. A new native library instead needs explicit direct
deps in every consuming binary/test. Linux libc interfaces need no new
unreviewed external library. New platform-only libraries or SDK APIs require
declared selected-platform inputs before use. Current SO_PEERCRED/getpeereid
logic proves UID checks only; declaring a new bridge does not prove process
incarnation or durable owner custody.

The complete runtime/test `ZIG_SOURCES` glob captures new Zig files. Narrow
explicit source lists still need any new transitive imports. New engine/native
actual-path tests should use the complete source closure plus `:native_api`,
native link options and runtime data, matching the existing actual-path tests.
Root owns BUILD mutations and proof batching; this reviewer owns only this
note unless explicitly reassigned.

Public source archive globs include this note, new Zig/C/header files, classified
Markdown, authority, native tracker JSON and goal JSON. New artifact packages
need their own explicit archive dependency because Bazel globs stop at nested
packages. Native support stays false until exact live gates pass. Any changed
API/catalog fact requires an actual `//:reference` producer and exact SPA import
comparison; documentation or schema generation cannot promote live support.

## R-N13 implementation release: pristine subset exporter

Root subsequently assigned only the new
`integrations/codex-upstream/export_pristine_subset.py` and
`export_pristine_subset_test.py` files to this workstream. R-N13 authorizes
their source mutations and this owned note update. Shared BUILD files,
manifest/validation, existing restoration/package implementations and the
preserved candidate source/artifact remain untouched by this writer. No test,
build or generator has been executed by this workstream.

The new CLI requires `--artifact-dir`, declared `--git` and `--ca-file`,
`--root` for an existing private durable restoration root containing its Git
mirror, and `--output-directory` for a new private durable sibling directory.
Repeat `--additional-original` for newly affected existing canonical
`codex-rs/` paths outside the old affected-file set. It reuses exact commit,
fsck, complete tree/blob verification and packaged-original comparison from
the existing custody tool. It does not read the prepared checkout. Existing
originals and attribution are mandatory; manifest-new files are not originals.
Additional duplicates, foreign/unknown paths and symlink blobs are rejected.
The archive is bounded to 4,096 regular files and the actual 64 MiB raw USTAR
budget, including padding and headers, before compression.

Successful export creates `pristine-originals.tar.gz` and
`export-receipt.json` exclusively, mode 0600, under a newly created 0700
directory. Existing epochs and destinations under the preserved root are
rejected. The receipt records fixed upstream identities, input patch digest,
complete Git object inventory digest, selected original modes/digests/sizes,
archive digest/size and `native_support: false`. Its
`prepared_source_verified: false` prevents a mirror receipt from claiming
prepared-tree custody. External exception messages and Git output are omitted
from diagnostics. Partial publication failure remains a failed epoch; the tool
does not delete or overwrite evidence to retry.

Nine focused unittest cases are authored but unrun: deterministic archive and
selected originals; traversal/foreign/duplicate selection; absent and symlink
blobs; pin/support/base/new-file mismatches; raw archive and file-count bounds;
duplicate JSON keys; preserved-root overlap; diagnostic redaction; and actual
exclusive private output with symlink/existing-epoch refusal. They do not
replace a real declared pinned-mirror export and final candidate reproduction.

Root's proposed host target must declare exporter as main, restoration and
patch parser as srcs, current patch/base/binary overlay/manifest plus
`@omux_host//:git` and CA as data, and bind these exact locations as arguments.
The focused Python test needs exporter/restoration/parser as srcs. A separate
`integrations/codex-owner-candidate` artifact package can expose its own
patch/base/binary overlay/manifest/validation/validation overlay and
`public_sources`. Root can declare a restoration target using the existing
upstream tool source with those new exact data labels; no second restoration
implementation or broad artifact-directory override is necessary. The root
source archive must explicitly include that package's public source filegroup.
Root controls wiring, source export, package generation, proof batching and
the first executable invocation.

## R-N13 explicit owner C platform and captured header inputs

Root reports the focused exporter gate passed (`cf80bcba` receipt prefix);
this reviewer did not execute it. The initial proposed platform parent
`//:local_linux` is private to the upstream root package. Root's first aquery
(`623df3fb` prefix) failed on that visibility boundary before any C action.
The corrected `//codex-rs/core:owner-linux` platform inherits public
`@platforms//host` and explicitly declares GNU 2.28 and Linux kernel 6.17
constraints. This is a selected proof profile, not a runtime kernel observation.

The official LLVM 0.8.11 graph declares GNU and kernel include directories as
toolchain argument data, disables standard library includes with
`-nostdlibinc`, and defaults its empty-sysroot setting to
`--sysroot=/dev/null`. Its original GNU 2.28 profile selects Linux 4.19.325
UAPI, which lacks `sys/pidfd.h` and the required modern pidfd macros. Root
ratified an explicit newer kernel profile while keeping GNU 2.28 libc ABI.
The exact added audited archives are `x86_64-linux-gnu.2.28.tar.zst`, SHA256
`8015f4a710987439dfdcde7539b62cc5db52d2cd9456af5e2e297494f13c56f3`, and
`6.17.13-x86.tar.zst`, SHA256
`2bb80502d70cadabd1efa0e0cd7ff826873fd787ab593f6394d6ada57248780a`.
The new manifest contains 13 archive entries; earlier 11-archive proof receipts
keep their own historical input scope.

Root's successful C-only aquery capture is
`/srv/fast-local/jess/state/codex/omux-codex-owner-development-20261004/owner-bridge-actions-57117d18.json`.
Root reports 18.617 seconds and zero executed actions. Read-only inspection
identifies target ID 1, `//codex-rs/core:native-peer-bridge`, CppCompile action
key `87162f093b1c5703656f09ec50edb4bf65c09a306d674444c8e00697faffee34`,
configuration ID 1, with execution platform `//:local_linux`. Its output is
`owner-linux-fastbuild`'s `native_peer.pic.o`; the execution-platform label
does not replace the selected target profile.

The action uses official LLVM 22.1.8 Clang, target `x86_64-linux-gnu`,
`-nostdlibinc`, `--sysroot=/dev/null` and explicit GNU 2.28/Linux 6.17.13
system include paths. Input depset 1 reaches those header directories through
depsets 2 and 3: artifact 3/path-fragment 8 is the kernel include directory,
artifact 4/path-fragment 10 is the GNU include directory. Artifact 13 is the
actual C source and artifact 14 the bridge header. The header directories are
configured declared inputs, not only command-line include strings.

The materialized pinned UAPI contains SO_PASSPIDFD 76, SO_PEERPIDFD 77,
PIDFD_GET_PID_NAMESPACE ioctl 5, PIDFD_GET_USER_NAMESPACE ioctl 9 and
PID_FS_MAGIC `0x50494446`. GNU 2.28's `bits/socket.h` imports `asm/socket.h`
and lacks the SCM_PIDFD enum. The assigned C writer owns the guarded modern
UAPI compatibility spelling and conditional missing-header portability; this
reviewer changed neither C source nor platform BUILD. Old headers must compile
unsupported stubs. Modern headers do not prove a supported running kernel.

This is header/source analysis only. The action retains an inherited Nix PATH;
no complete executable-search or remote closure provenance claim follows from
the inspected header predicate. Root's separate actual C build is pending in
this note. Compiler success, whole candidate inventory, protocol reconciliation,
installed checkpoint and live/native support remain separate predicates.

Current source comparison against the preserved prepared baseline identifies
four additional pristine originals outside the old candidate manifest:
`codex-rs/app-server/src/in_process.rs`, `codex-rs/core/BUILD.bazel`,
`codex-rs/core/src/session/handlers.rs`, and
`codex-rs/core/src/tasks/mod.rs`. The current six new code files are
`codex-rs/app-server/src/owner_control.rs`, and core's
`auth_broker_owner_tests.rs`, `native_owner_startup_tests.rs`, `native_peer.c`,
`native_peer.h`, `native_peer.rs` under `codex-rs/core/src/`. Packaging must
retain the old explicit new schema paths; `auth_broker.rs` remains the producer's
default new file. Generated owner schema exports may add further paths. This
list describes the inspected editing epoch, not a final frozen inventory.

## R-N13 declared formatter and local test-toolchain resolution

The existing public `@rules_rust//tools/upstream_wrapper:rustfmt` target in
the actual rules_rs-reexported rules_rust source declares the selected rustfmt
toolchain files as runfiles. Its Rust launcher resolves the declared tool and
runs it in `BUILD_WORKING_DIRECTORY`. Root can use this target through the
locked upstream shell with explicit `--edition 2024`,
`--config-path codex-rs/rustfmt.toml`, `--config skip_children=true`, and only
the frozen changed Rust paths. This preserves candidate edition/configuration
and prevents module traversal into unowned files. A second declared invocation
with `--check` can verify the same path set. The check-only rustfmt aspect
consumes a whole selected crate and does not provide a changed-file selector.
No formatter was executed by this reviewer; direct Cargo, DotSlash and
upstream `scripts/format.py` remain outside the requested lane.

Full source inspection of the pinned Bazel `tools/test/BUILD` confirms that
the default test toolchain normally copies all target-platform constraints to
test execution-platform selection. A header-only kernel 6.17 target constraint
therefore requires an explicit local test mapping when the existing Linux
execution platform does not carry it. Root declared
`//codex-rs/core:owner-local-test-toolchain`, backed by
`@bazel_tools//tools/test:empty_toolchain` and
`@bazel_tools//tools/test:default_test_toolchain_type`. Its target constraints
are Linux/x86_64/GNU 2.28/kernel 6.17; execution constraints are Linux/x86_64.
The standard empty provider contains no executable or tool data.

Root's explicit
`--extra_toolchains=//codex-rs/core:owner-local-test-toolchain` resolves this
mapping without changing all host compiler profiles or header input selection.
It does not assert a running kernel 6.17, replace actual feature probing on the
reported runtime kernel, or authorize remote scheduling. Private peer tests
must still pass their runtime socket/pidfd predicates. The rule resides in
the already selected additional original `codex-rs/core/BUILD.bazel`, so the
packaging path list does not expand for this resolution change.

Root reports C invocation `980d222c-d5e8-40c2-8d9d-d6b0daaa4466` failed
at a libc/kernel `f_owner_ex` struct collision, 16.609 seconds; the narrow
portability correction has its own writer. Production compilation invocation
prefix `2b3d1df2` was continuing when root reported three unit-bin analysis
failures from test-toolchain resolution. Neither the failed C invocation nor
those analysis failures establishes passing C/Rust/runtime predicates. Fresh
actual compilation and tests remain root's responsibility. R-N13 authorizes
this note-only mutation; candidate source and graph were not changed here.

R-N13 subsequently authorized separate candidate artifact tooling after root's
live Omux invocation ended. This lane added the declared bounded
`//integrations/codex-upstream:import_schema_bundle` byte-copy tool and focused
fixtures, plus `integrations/codex-owner-candidate` with a manual artifact
verifier, synthetic tooling test, README and candidate-specific restoration
target. Old product artifacts, validation metadata and prepared source were
preserved. The importer accepts exact stable/experimental native Rust outputs,
performs no normalization or recompression, preserves unrelated files and
publishes an exclusive private intent and final byte receipt. The candidate
oracle reconstructs the exact changed subset, verifies attribution and
artifact/validation/schema receipt binding, and keeps full-tree restoration
and behavioral tests separate. These authored tools are not passing execution
or live-support evidence; root owns their declared checks.

The new `NativeOwnerPending` error can affect generated schemas beyond the
previous 107-file candidate. Root therefore released the narrow exporter
`--include-schema-originals` extension after reporting the eight-target Omux
run completed. The flag unions all original pinned Git blobs under the exact
`codex-rs/app-server-protocol/schema/` prefix ending in `.json`, `.ts` or `.zst`
with existing selections. It reads no edited checkout. Already selected schema
originals are included once; explicit duplicate requests still fail. Every
selected path retains canonical-source, regular-Git-mode and original-byte
custody checks, with the existing 4096-file and 64 MiB raw-archive bounds.
The authored focused fixture covers inclusive unchanged schemas, prior
selection overlap, unrelated exclusions, substituted originals, symlinks and
both budgets. Packaging still omits unchanged files when comparing these
originals with the edited checkout. No build, test, generator or host invocation
was executed by this lane for this change. R-N13 authorizes these tooling and
durable-note mutations; current checks and candidate publication remain root's
responsibility.

R-N13 released a narrow restoration correction after root reported candidate
verify-prepared invocation prefix `9b9c8062` rejected the actual owner-platform
convenience links. `restore_source.py` now accepts only the exact reviewed
`local_linux-fastbuild` and `owner-linux-fastbuild` link profiles. The former
remains the default when an output base is supplied. An explicit profile is
valid only with `--phase verify-prepared --bazel-output-base`; successful
receipts record the chosen profile. The four links still require exact owned
symlinks to their canonical descendants under that output base. Unknown or
traversing profiles, redirects, wrong-profile links and non-links remain
rejected. Focused fixtures cover both profiles and argument misuse. This lane
executed no checks or restoration retry, and preserved all artifact, product
and prepared-source bytes. Root owns the focused declared test and subsequent
full candidate-source verification; the failed epoch remains separate.
