# Declared macOS toolchain and development bundle

The SwiftUI client uses a Darwin-only Bazel compile action. It does not discover
Xcode, invoke an ambient Swift compiler, or use `xcrun` to find tools or an SDK.
The locked Nix flake supplies Swift 5.10.1 and the matching Apple SDK 14.4;
the experimental application's minimum macOS version is 14.0, matching the
locked Nix runtime closure. This minimum is a bundle compatibility requirement;
it does not establish runnable or installed Darwin support. The pinned nixpkgs Swift
compiler itself selects `apple-sdk_14` as the SDK available when that compiler
shipped. SDK 15 or 26 must not be substituted without compiler compatibility
proof.

The declared Darwin compilation path uses the coordinator and an
operator-configured REAPI worker on PZM. It is currently held. The user reports
that GF's coordinator seat on Neo owns the TIN-2998/GF#1717 context, with
`startServices=false` and worker activation blocked on a dedicated 4 GiB APFS
quota volume, mTLS/JWKS files, the shared operation lock and 168-hour burn-in
evidence. This is attributed operator context, not a
fresh host observation. No Omux build instruction authorizes service activation,
GC, host transport or a change to that hold. Neo remains a read-only source for
established lab patterns and immutable inputs. See the [recorded operator context
and graph evidence](../implementation/native-evening-evidence-2026-10-03.md).

The prior source epoch's complete archive-producer analysis passed strict
validation under `3ebf9dcc-e8cb-4c22-9c28-0b6d70e971c2`, without dispatching
Darwin actions. Coordinator registration of the exact selected closure covers
128 recursive paths; complete PZM registration and an independently verified
selected-worker/operator-route binding remain unproved. Accepted analysis does
not establish executed input digests, remote execution, artifact bytes or
installed behavior, and does not certify later runtime source changes.

Only after the operator releases the lane and establishes registration,
selected-worker binding and SDK authorization may the following declared build
shape be used. Set `OMUX_REAPI_OPERATOR_RC` to the private operator Bazel
configuration, `OMUX_DARWIN_BAZEL_CLOSURE` to the exact locked Darwin closure,
`OMUX_BAZEL_OUTPUT_USER_ROOT` to the operator's durable isolated Bazel output root
and `OMUX_BAZEL_INVOCATION_ID` to the receipt UUID. Endpoints, credentials and
routing configuration remain private operator inputs. See
[worker custody](../../tools/nix-workers.md) for separate coordinator bootstrap
and execution inputs. The remote profile disables local fallback.

```bash
nix develop --ignore-environment --keep HOME --command bazelisk \
  --nosystem_rc --nohome_rc \
  --output_user_root="$OMUX_BAZEL_OUTPUT_USER_ROOT" \
  --bazelrc="$OMUX_REAPI_OPERATOR_RC" build --config=darwin-reapi \
  --config=reapi-proof \
  --invocation_id="$OMUX_BAZEL_INVOCATION_ID" \
  --repo_env=OMUX_BAZEL_CLOSURE="$OMUX_DARWIN_BAZEL_CLOSURE" \
  //clients/macos:control //clients/macos:Omux //clients/macos:archive
```

When execution is admitted, the first target compiles the complete SwiftUI client.
The second emits the
declared `Omux.app` directory artifact, including `Omux`, `omux`, `omuxd`,
`Contents/Library/LaunchAgents/ai.xoxd.omux.daemon.plist`, and an Info.plist whose
version derives from `src/product.zig`. `CFBundleShortVersionString` holds the
numeric version; `OmuxProductVersion` preserves its prerelease suffix. The
service is registered explicitly through `SMAppService`; quitting the controls
does not unregister it.

The application action resolves actual Mach-O load commands, copies transitive
Nix dylibs into `Contents/Frameworks`, and rewrites dependency edges to paths
relative to their loaders. Apple system libraries/frameworks remain system
dependencies; SDK files are never bundled. Declared Nix `otool` and
`install_name_tool` inspect and rewrite the files. The action removes inherited
search paths, checks architecture and deployment metadata compatible with macOS
14.0, and rejects
dependencies outside its declared closure.

Declared Nix `rcodesign` then emits an ad-hoc application resource seal and
embedded Mach-O signatures. It uses an empty explicit configuration, a scrubbed
environment and no timestamp server or signing identity. The archive target
packages that actual `.app` TreeArtifact as `Omux-macos-arm64.zip` or
`Omux-macos-x86_64.zip`, with stable member timestamps and executable modes.

## SDK custody

`@omux_apple` consumes the same immutable `OMUX_BAZEL_CLOSURE` as the native
C/C++ graph. Its manifest declares the SDK path, SDK version, Swift compiler
path and Swift version. The repository requires the SDK and compiler roots
to appear in the flake's transitive `store-paths` closure and validates the
SwiftUI and ServiceManagement frameworks before compilation. The full declared
closure is a Bazel action input, including compiler support files and libraries.
Packaging-tool roots must appear in that same closure.

The SDK lives below its immutable package output at
`Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk`. `DEVELOPER_DIR`, `SDKROOT`
and the target triple are explicit; `SWIFT_DRIVER_CLANG_EXEC` supplies the
declared Nix compiler driver. Module caches belong to the individual action.
The generated `@omux_apple//:custody.json` records those inputs and is included
in `Contents/Resources/apple-toolchain-custody.json`.

The locked nixpkgs SDK definition records Apple's download URLs and a fixed
recursive SDK source hash. These inputs establish reproducibility, not a new
license grant. Builders must have authorization to use the Apple SDK; Omux
does not vendor or redistribute that SDK. Before the held PZM lane can dispatch,
its selected REAPI worker must have the same recorded Nix closure registered and
satisfy the same custody requirements.
Configured platform properties and a passing analysis do not prove that the
scheduler selected that worker or that any action executed there.

## Remaining Darwin proof gates

Linux builds skip the macOS-constrained targets. Forcing them onto a Linux
execution platform fails with the missing Darwin/SDK capability; this never
produces a substitute executable or a simulated successful build.

The output recipe produces an **ad-hoc signed development bundle**, not a
trusted macOS release. `runtime-relocation.json` records the copied dependency
closure and labels signature checking as structural. `rcodesign verify` is not
used as a substitute for Apple verification: its bundle verification is
unsupported. Developer ID signing, notarization, Apple platform acceptance,
service registration and approval, daemon reconnect behavior and uninstall
restoration remain separate gates.

The Linux-capable `//clients/macos:bundle_test` suite checks metadata assembly,
transitive relocation planning, custody rejection and deterministic archive
behavior. `//clients/macos:macho_test` checks thin/universal byte formats and
malformed metadata. Universal files with different search paths per slice fail
closed until an architecture-specific relocation recipe exists. Neither suite
executes Darwin tools or proves a runnable macOS app. The complete compile,
rewrite, ad-hoc signing and runtime path still requires execution on Darwin.
