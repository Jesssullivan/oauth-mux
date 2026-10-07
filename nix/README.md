# Declarative fleet delivery inputs

`consume-bazel-artifact.nix` consumes an **already verified and extracted**
`//delivery:release_archive` bundle. Supply its directory, recursive NAR SHA256,
exact source revision and `development` or `release` channel. The NAR digest binds every
file including the delivery manifest. Obtain the hash and extract/verify only
through declared Bazel delivery actions. This consumer performs no compilation,
archive unpacking, network access or nested Bazel bootstrap. Nix materialization
only links immutable Bazel output into a package interface.

The consumer requires a portable Linux bundle with the daemon, native host, CLI
and genuine thin Qt UI. Both channels remain experimental. Release channel
additionally requires clean stamped provenance; it does not mean a stable release
or establish application continuity. Darwin is explicitly unsupported here.

Root flake integration can export:

```nix
homeManagerModules.omux = import ./nix/home-manager.nix;
lib.consumeBazelArtifact = args: import ./nix/consume-bazel-artifact.nix args;
```

Call the consumer with locked `pkgs`, then pass its resulting package to
`programs.omux.instances.development.package` or `.release.package`. Enable the parent
`programs.omux.enable` and chosen instance `.enable`, set one exact `.extensionId`
and optionally `.chromiumConfigDirectories` (for example `chromium` and
`google-chrome`). Concurrent channels require different extension IDs.

Home Manager owns package launchers, user service definitions and host manifests.
The immutable launcher fixes `OMUX_INSTANCE=default|dev`; runtime selection owns
separate state roots, socket namespaces and wrapping-key namespaces. The service
names and native host names are `ai.xoxd.omux` and `ai.xoxd.omux.dev`; CLI and UI
commands use `-dev` suffixes in development. Existing HOME and native session
stores remain in place. Service startup uses the user runtime directory.

No credentials, identity enrollment, source consent, database, wrapping keys or
renewal state enter the Nix store or declarative configuration. Removing this
module removes its managed installation objects; runtime forget and secret
deletion remain explicit daemon operations. Generation rollback cannot restore
credential generations or erase forget tombstones. Declarative installation is
source implementation until evaluation and installed activation gates pass.

`ownership-witness.nix` constructs a bounded immutable installation record from
the consumer's verified artifact metadata. Home Manager places an inspectable
link at `omux/instances/<channel>/installation.json` under XDG configuration.
Launchers provide its direct immutable store path through `OMUX_INSTALL_RECORD`
and the raw imported artifact root through `OMUX_INSTALL_PREFIX`. These are
startup hints: runtime inspection must verify immutable record custody, every
listed payload digest and the actual executable before reporting ownership.
The record binds channel, source revision, NAR and manifest digests. Its desired
service and browser labels do not prove the installed service or registration.
Service inspection remains independent; generation changes never restore live
credential generations, renewal ownership or forget tombstones.

`evaluation-tests.nix` accepts the locked `pkgs` and evaluates the module without
building or activating its packages. It checks exact origin registration,
isolated host/service paths, private service mode, channel/package mismatch,
duplicate extension rejection and unsafe browser directory rejection. Its small
option harness exercises nixpkgs module evaluation; installed Home Manager
evaluation and actual activation remain separate acceptance gates. Wire it to a
declared Bazel test with Nix, locked nixpkgs inputs and these source files in the
action closure; no standalone invocation or new network-resolved inputs.

The declared runner is `evaluation_runner.py`. It verifies the selected source's
NAR SHA256 against the exact nixpkgs node in `flake.lock` before importing it.
Its evaluator uses `dummy://?read-only=false`, offline mode, disabled import from
derivation, empty builder/substituter lists and zero build jobs. The writable
dummy setting permits only ephemeral in-memory derivation objects; it does not
activate a filesystem store or shared builder. It cannot fall back to the shared
daemon when evaluation is unavailable. The official [dummy-store contract](https://nix.dev/manual/nix/2.34/store/types/dummy-store)
and [NAR hashing command](https://nix.dev/manual/nix/2.34/command-ref/new-cli/nix3-hash-path)
describe these boundaries; compatibility with the locked executable still requires
the declared gate.
Output and duration are bounded; interrupted descendants are terminated.
`evaluation_runner_test.py` tests these boundary predicates without invoking Nix.

Root target wiring uses `python_test` with the runner as main, `evaluation-tests.nix`
and `home-manager.nix` as data, plus `@omux_host//:nix`, `@omux_host//:all_tools`,
`@omux_eval_source//:source-input.json`, `@omux_eval_source//:source_files` and
`flake.lock`. Supply location-expanded `--nix`, `--source-input`, `--lock` and
`--expression` arguments. The test should be local/coordinator
only, since the locked host source and Nix executable describe that platform.
The pure Python boundary test uses the runner as a declared source input.

`tools/nix_evaluation_source.bzl` declares an already cached immutable source
independently of normal tool closures. Supply `OMUX_NIXPKGS_EVALUATION_SOURCE`
or the repository rule's explicit `source` attribute. The rule inventories source
files with the existing declared bootstrap Python and records verification as
pending; only the Bazel action verifies its NAR. It never fetches, evaluates Nix,
realizes a new bootstrap closure or manufactures store outputs. The ordinary
bootstrap closure remains unchanged. A missing or wrong source fails the gate.
No hashing or module evaluation has been performed in this source work.

`tools/nix_source_probe.py` is a separate local operator metadata probe for
finding cached source candidates. Its guarded Bazel invocation reads the Nix
SQLite database through `mode=ro`, compares only the exact lock-derived SHA256,
checks a bounded set of existing source paths and emits no database contents.
It does not contact a Nix daemon, fetch inputs, hash bytes or establish release
evidence. Passing its candidate into the declared source repository still
requires the authoritative NAR action before module evaluation.

Service definition witnesses derive automatically. `service-witness.nix` binds the final
merged unit fields, Home Manager's actual generated source path, artifact
manifest digest, instance and exact installed unit/login paths. Its scope is
`definition-only-not-activation`. The daemon receives static service hints;
other launchers discard them. The separate record avoids a unit/launcher/store
dependency cycle. Runtime verification must hash the actual immutable unit and
independently inspect the installed links and live service. Neither a desired
unit nor a passing modeled fixture establishes activation.

The lightweight evaluation harness supplies explicitly synthetic generated unit
sources. Its service-witness fixtures model serialization and bindings only. A genuine
Home Manager evaluation needs separately declared, NAR-verified pinned Home
Manager source. Lab's root lock currently selects Home Manager revision
`65258d5c65a250189fde2e35f490d15e064c4c62` with NAR hash
`sha256-Sxu1NLTD/Ern6hFGLlZmtKCSct3YQXZI/lls8RE1XeM=`; this observation neither
adds that input to Omux nor qualifies cached source bytes. Real activation
links through `home-manager-files` remain unknown under the initial direct-link
collector contract. Optimized hardlinked witnesses also remain unsupported.
Qualification must document actual link topology before broadening verification;
it must not activate services on the host merely to satisfy a fixture.
