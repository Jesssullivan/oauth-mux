# Codex adapter delivery — current source epoch, 2026-10-05

Authority: [AGENTS.md](../../AGENTS.md), the user's Omux-owned adapter correction,
and the [native lifecycle reset](../../docs/plans/omux-native-account-lifecycle-reset-2026-10-02.md).
Linear carriers: [TIN-5338](https://linear.app/tinyland/issue/TIN-5338),
[TIN-5421](https://linear.app/tinyland/issue/TIN-5421), and complete continuity
[TIN-2057](https://linear.app/tinyland/issue/TIN-2057).
The [durable implementation record](../../docs/agent-notes/2026-10-05-sess-omux-integrated-delivery.md)
owns execution chronology and evidence digests. These artifacts do not close
native acceptance or establish shipped support.

Omux implements the authentication integration contract and application adapter.
Delivery may use an adequate existing mechanism or an explicitly maintained
application modification. This lane develops modified Codex; no vendor-supplied
Omux hook is assumed, and unmodified Codex continuity remains unsupported by
available evidence. Ordinary launch, native session/history and accepted work
remain the product boundary.

## Current prepared source

`//tools:codex_fresh_source_producer` passed in epoch
`cf85bdc6-5de0-4033-a57e-5e8d24301ccb`, exit zero with empty descendants and
preserved evidence. Its complete, **uncompiled** candidate contains 8,546 files
and 84,615,686 source bytes. Source receipt SHA-256:
`6a606a9ca602e31f0050d15625038eeaaaff96432248dd803d51c3a1838871b3`.
It binds upstream commit `00c972ed5d6ff6499317fd41b7f23605b8e6850d`, tree
`6fa1a3767a92ba5d579fcaf724fdce3049c2070b`, the reviewed recovery delta and
the applied retirement transform. The preserved development SDK and historical
candidate/runtime receipts were not modified.

Retained artifact root:

```text
/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/cf85bdc6-5de0-4033-a57e-5e8d24301ccb/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/codex_fresh_source_producer/test.outputs/codex-adapter-epoch
```

The root contains `source/`, `source-receipt.json`, `full-product.patch`,
`product-binary-overlay.tar.gz` and `validation-overlay.patch`.
[The producer](../../tools/codex_fresh_source.py) combines verified pristine
source, pinned candidate and validation overlays, reviewed recovery delta and
[retirement transform](retirement_delta.py); it invokes no SDK compiler or provider.
The receipt's process-wrapper creation path is provenance only. Consumers
validate and use the retained `source/`, never the creation path.

Actual descriptor production in epoch `d8471e28-cc1b-4d29-90ec-5d3faa25531a`
verified the complete tree before and after enumeration: paths, bytes, symlink
targets and uniform physical `0555` modes on regular files and directories.
Git `100644`/`100755` modes remain separate authority in the digest-bound source
receipt. The explicit policy is
`bazel-retained-export-all-regular-and-directories-0555-v1`. Exported files that
were nonexecutable in Git are physically executable; only declared SDK tools
are dispatchable. Source and receipt bytes were unchanged.

## Declared producer and SDK sequence

The current graph is [tools/BUILD.bazel](../../tools/BUILD.bazel). Execution uses
locked Nix/Bazel inputs and the existing contained controller; producers never
invoke nested Bazel.

1. `//tools:codex_pristine_source_producer` supplies verified originals. Actual
   epoch `01c11682-8389-4519-9b1a-dc7403066431` produced 8,497 original files /
   84,097,652 bytes. Gzip SHA-256:
   `dbe1a1ec6ce7c6a981b5adf2410be4ae68f8bc906b1dec6b5e65a78efbc3292d`;
   receipt SHA-256:
   `8a66e297631d2767e373e0fd8cfe9c7764dbb6357bb2cf61033a6cde1d0a61ba`.
2. `//tools:codex_recovery_delta_producer` supplies the reviewed scoped delta.
   Patch SHA-256:
   `aa4bc7f3cdd281a34096260ff60dd17dfdc892c55e59e282989110383e701cf5`;
   receipt SHA-256:
   `897ddcad5fac986aa5db611d1ebe4464563abe46eb74006090427f836352f521`.
   Seven changed files / 94 selected code inputs are not a complete SDK proof.
3. `//tools:codex_fresh_source_producer` prepares the exclusive source epoch
   above. Successful retained artifacts are declared inputs; rerunning old
   producers or editing preserved SDKs does not replace their custody.
4. `//tools:codex_sdk_settings_producer` binds locked flake/Nixpkgs and eight
   available tool executables. Actual receipt SHA-256:
   `c897934ef7c8d6050f64d0e8e906654774c8d2aa4b2aaa25d8074948fe57b511`.
   The verified thirteen-archive bundle supplies compiler inputs, not dependency
   closure. [Descriptors](../../tools/codex_sdk_dependencies.py) and
   [offline cache qualification](../../tools/codex_dependency_cache.py) expose
   remaining objects without fetching or using mutable SDK repositories.
5. After storage admission and offline input qualification, select the finite
   `codex-sdk` profile and lane through
   [the SDK validator](../../tools/codex_sdk_profile.py) and
   [controller](../../tools/execution_guard.py). They bind source/settings/archive
   receipts, full source inventory and physical policy; use an independent
   current-controller output base; and verify an immutable-Bash launcher that
   prints the fixed commit with no Git fallback.

Initial finite SDK lanes are protocol
`//codex-rs/app-server-protocol:app-server-protocol-unit-tests`, core
`//codex-rs/core:core-unit-tests`, and app-server
`//codex-rs/app-server:app-server-unit-tests`. The profile fixes
`//codex-rs/core:owner-linux`,
`//codex-rs/core:owner-local-test-toolchain`, optimization, lockfile error mode,
one build/test job and one Rust test thread. `owner-linux-opt` is a historical
restoration output profile, not an SDK `--config`. Reviewed finite flags replace
ambient rc files; test PATH and verified distdir are declared. Effective
`PrivateNetwork=yes` covers the entire workload, including repository analysis;
missing offline repositories fail closed.

Native SDK execution remains held while approved storage allocations are below
admission floors. It has not run in this source epoch. There is no HOME build
bypass, quota change, old-binary substitution or vendor-hook dependency.

## Dependencies and remaining native gates

The actual descriptor manifest is 692,243 bytes, SHA-256
`50db24e82808bfea9fd00f20325874962519c76ea8d6c0e2ca2eb311a77b0feb`.
It enumerates 1,596 public artifact descriptors and 79 initially unresolved
entries. Actual cache qualification observed home cache 274 verified / 1,446
missing / zero refused and owner cache 189 verified / 1,430 missing / zero
refused. These are independent observations, not additive closure proof. Git
sources, BCR archives and dynamic repository inputs still need declared immutable
qualification. Protocol itself depends on Git-backed `nucleo` through native
rollout/file-search libraries.

The retirement transform repairs
`thread_manager.rs::shutdown_all_threads_bounded`: snapshot shutdown retains
the original runtime Arc and removes an entry only if `Arc::ptr_eq` still
matches. Native regression remains **UNRUN**: delay A's shutdown, replace its
thread-ID entry with B, complete A and observe B remains; also cover unchanged
A, failure/timeout and stale detach authority. This map repair alone does not
prove the daemon's owner/epoch/generation barrier.

Fresh native concurrency tests, stable/experimental schema generation and six
attachment-status schema imports remain **UNRUN**. Selected CLI build,
runtime archive/manifest/receipt, and installed discovery/TUI/resume results for
these exact source bytes also remain **UNRUN**. Their producers must enter the
finite contained graph before dispatch; a source receipt does not admit
arbitrary SDK commands.

Then bind a new selected runtime to
[the recovery runtime lane](../codex-native-recovery-runtime/README.md) and prove
`//delivery:installed_native_recovery_discovery_test` and
`//delivery:installed_native_tui_test` against those same bytes. The fixture uses
real native `/export` before `/rename`, preserves original rollout metadata,
and waits at most ten seconds for the exact cold-resume checkpoint. It never
seeds or rewrites native history. Empty-history provider-free proof does not
establish preservation of accepted nonempty history, tools or approvals, or
same-process account replacement. These live gates remain **UNRUN**; provider
evaluation is a separate finite authorization lane.

Capability booleans establish protocol compatibility, not version-qualified
delivery/support. Existing runtime packaging binds the upstream commit and
executable digests. Installation still needs a channel-qualified selected-runtime
carrier checked against the native peer before delivered adapter support can be
claimed. The current discovery field `hook_compatible` grants no such claim.

The installed selection must derive from verified package and ownership evidence,
binding channel/target, manifest/archive/source/producer digests, upstream commit,
packaged backend and loader identities, installation transaction and adapter
epoch. Peer-claimed version or digest fields cannot establish that selection.
Selection drift during recovery must retain custody and report incompatibility;
it must not overwrite native history or retire unresolved ownership.

Live executable attribution is a separate unresolved gate. The current
[launcher](../codex-owner-runtime/runtime_package.py) explicitly execs its
bundled loader before the backend. Therefore a lone `/proc/PID/exe` hash cannot
be assumed to identify `lib/codex/libexec/codex.bin`; the actual packaged launch
profile needs its own proof. Existing socket-derived pidfs/namespace witnesses
establish process incarnation and packet writer, not executable/version identity.
The pinned [Linux 6.17 pidfd UAPI](https://raw.githubusercontent.com/torvalds/linux/v6.17/include/uapi/linux/pidfd.h)
has no executable-FD or exec-generation field. A saved selected-runtime carrier
alone cannot promote delivered adapter support. These are source-audit findings,
not a new installed native result or an implemented selection protocol.

## Historical inspection and preserved evidence

Early October 5 inspection of the preserved development source found
thread-ID-only shutdown removal. [The original proposal](retirement-barrier-20261005.patch),
[scoped path inventory](source-code-path-inventory-20261005.txt) and
[observed pre-retirement diff](thread-manager-observed-diff-20261005.patch)
retain that provenance; they do not describe current cf85 source state.
The pure transform passed in root invocation `afcddb75`. Earlier claims that
retirement was unapplied or a complete edited-source receipt was absent are
superseded by cf85, not converted into native proof.

Frozen 107/164 artifacts, runtime009, installed P1, source T2 and their receipts
remain historical evidence. Old availability tables, network-fetch proposals
and binary-run restoration instructions are superseded operational material.
Current tools, declared targets and the linked durable record replace them.
No full Codex source is vendored here and no native user store was copied into
the source epoch.
