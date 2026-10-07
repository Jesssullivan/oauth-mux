# ADR-007 — Nix/Bazel local execution authority

Status: ratified direction, 2026-10-02; experimental and unshipped.

**Existing user decision.** Every build, test, generator, package, executable invocation and check runs through Bazel/Bazelisk with tools from the locked Nix flake. Local sandboxed execution is the proof default. Automatic CI build/test/check workflows, Just, standalone Zig builds and former GF proof dispatch are retired.

**Implementation choice.** One declared Bazel graph covers runtime, adapters, clients, extensions, generators and packaging. Compiler actions use declared inputs and scratch caches; platform SDKs are explicit inputs. Future RBE/REAPI retains the action graph and digest-addressed closures, with endpoints/credentials only in operator configuration. Publication is explicit and artifact-driven.

**Acceptance / unresolved proof.** Recorded local results prove only their predicates and sandbox limits. Future remote readiness is an architectural requirement, not an exercised remote backend. Cold-cache closure, additional platforms and remote execution remain separate proof/operational decisions. Documentation changes do not justify invoking removed scripts or direct host tools as validation.

**REAPI evidence limits.** An analyzed execution-platform label or configured
`nix_closure` property proves declared selection only. In pinned Bazel 9.0.1,
[the expanded spawn logger](https://github.com/bazelbuild/bazel/blob/9.0.1/src/main/java/com/google/devtools/build/lib/exec/ExpandedSpawnLogContext.java)
obtains platform properties from the submitted spawn through
[SpawnLogContext.getPlatform](https://github.com/bazelbuild/bazel/blob/9.0.1/src/main/java/com/google/devtools/build/lib/exec/SpawnLogContext.java).
Matching those properties in a successful remote receipt does not independently
identify the selected worker. Actual routing proof also requires a selected-worker
identity, such as server `ActionResult.execution_metadata.worker`, independently
bound to the operator route and exact registered closure. The provenance helper
reports `receipt_platform_properties_match` and keeps `worker_routing_verified`
false. Fresh remote execution, remote-cache acceptance, complete declared regular
input/digest accounting, final artifact bytes and installed behavior remain
separate predicates. Repository bootstrap and complete tree-output materialization
are outside the helper's proof.

The pinned [analysis schema](https://github.com/bazelbuild/bazel/blob/9.0.1/src/main/protobuf/analysis_v2.proto)
uses proto3 string fields for environment pairs, so an omitted aquery value
decodes as the empty string. This default applies only to analyzed metadata.
The [expanded JSON writer](https://github.com/bazelbuild/bazel/blob/9.0.1/src/main/java/com/google/devtools/build/lib/util/io/MessageOutputStreamWrapper.java)
prints fields without presence; missing values in execution receipts remain
rejected rather than acquiring an inferred value.

Archive analysis must query `deps(//clients/macos:archive)` and include parameter
files. A bare target query can omit required dependency producers, as described
by the [pinned aquery documentation](https://github.com/bazelbuild/bazel/blob/9.0.1/site/en/query/aquery.md).
Accepted producer reachability and declared regular-file paths are analysis
predicates; they do not attest executed input contents or remote worker identity.

The locked Nixpkgs [Bazel action-environment patch](https://github.com/NixOS/nixpkgs/blob/0726a0ecb6d4e08f6adced58726b95db924cef57/pkgs/by-name/ba/bazel_9/patches/strict_action_env.patch)
sets a coordinator utility PATH. Selected C/C++ features therefore bind PATH
to only the selected manifest's coreutils output directory, already declared in
toolchain inputs. Pinned [CppCompileAction](https://github.com/bazelbuild/bazel/blob/9.0.1/src/main/java/com/google/devtools/build/lib/rules/cpp/CppCompileAction.java)
overlays feature environment after configured environment. The pinned
[rules_cc link finalizer](https://github.com/bazelbuild/rules_cc/blob/0.2.18/cc/private/link/finalize_link_action.bzl)
and [strip implementation](https://github.com/bazelbuild/rules_cc/blob/0.2.18/cc/common/cc_helper.bzl)
supply feature environment; [SpawnAction](https://github.com/bazelbuild/bazel/blob/9.0.1/src/main/java/com/google/devtools/build/lib/analysis/actions/SpawnAction.java)
keeps explicit values over inherited values. The selected Nix compiler wrapper
adds its declared bintools and utility inputs before invoking its absolute
compiler. A local adversarial-default smoke exercises C/C++ compilation,
executable linking, static archiving and stripping; additional action environment
coverage is analysis-only.

Pinned Skylib 1.9.0 [run_binary](https://github.com/bazelbuild/bazel-skylib/blob/1.9.0/rules/run_binary.bzl)
copies the default shell environment even when shell inheritance is disabled,
then overlays its explicit environment. The owned `tools/arocc.BUILD.bazel` overlay
sets PATH empty only for the pinned in-process definition generator, which reads
and writes declared files without spawning another executable. Its actual Linux
smoke and accepted Darwin analysis remain distinct from Darwin execution. These
R-N13 fixes change declared action environments, not provenance acceptance rules
or the authorized closure.

Authority: [reset, toolchain and delivery](../plans/omux-native-account-lifecycle-reset-2026-10-02.md); [build graph](../../BUILD.bazel); [evidence](../implementation/native-reset-evidence-2026-10-02.md). Related: [ADR-005](005-custody-and-runtime.md).
