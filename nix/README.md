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
adds that input to Omux nor qualifies cached source bytes.
The Linux collector now implements bounded direct-store and one selected
`home-manager-files` generation-hop inspection, including same-generation
service-record/unit/login joins, current named/held witnesses and exact unit
bytes. It accepts immutable root-owned store files with stable hardlink counts;
mutable files and symlinks retain their stricter custody rules. These source
predicates and their fixtures do not prove a genuinely realized or activated
Home Manager generation. Genuine isolated realization, activation, update and
removal remain separate gates, as do live service readiness and exact-ID browser
installation. Do not activate a fleet service merely to satisfy a fixture or
use the portable installer to replace declaratively owned objects.

A separate experimental input-content gate is declared as
`//tools:home_manager_linux_realization_inputs_producer`. Its selector starts
null. It requires the complete reference closure of explicitly selected pinned
HM/nixpkgs sources, the portable artifact, a proposed generation derivation,
and the locked Bash/Nix runtime. The gate verifies every declared member and
NAR, copies the complete closure into an owned disposable private store, and
compares actual import-registration readback. Existing private-store scaffolding
supplies this registration ABI; its presence is not proof of a complete HM build.
The proposed derivation's HM origin and builder semantics remain unqualified.
No evaluation, generation build, activation, update, removal, service readiness,
or browser registration occurs in this gate. Genuine generation and lifecycle
actions remain subsequent declared work; the dummy-store evaluator and managed
ownership policy are unchanged.

The next declared gate is
`//tools:home_manager_linux_generation_catalogue_producer`, under
`home-manager-generation-catalogue-reserved`. It reuses the same cold input
selector and complete isolated registration, requires separately successful
current paired-source/artifact producer provenance, and forces the actual
`home.activationPackage.drvPath` from the new generation expression. It derives the first
proposal itself; the old selected `.drv` remains historical input with no HM
generation authority. Actual generated public `.drv`/source bytes and registration
records are retained in the acquisition request, before private-store cleanup. The original dummy evaluator is
unchanged. Its fixed proof username/home and extension ID are generation
configuration, not an installed user or browser admission.

The action emits an exact version-bound acquisition request from actual Nix
2.34.6 recursive derivation JSON and isolated fixed-output bindings. Required
derivation output roots are explicit: they are not implied by a `.drv` reference
closure or by `all_tools`. Missing output roots and their full reference/NAR
closures still need a subsequent declared content acquisition. The request
never qualifies their bytes, a complete builder closure, a realized generation,
or activation/update/removal. It performs no builder or activation command.
Actual source/producer exit, model checks and private-store evaluation remain
unrun until the coordinator executes their declared gates.
