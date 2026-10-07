# Local experimental delivery

The successor is experimental. These actions package the host-built binaries
and do not turn native integration fixtures into live continuity evidence.
Stable v0.1.15 download names and installation instructions remain in the
source-generated reference bundle as historical release facts.

The [current provider-free native/browser continuation](../docs/plans/omux-native-browser-continuation-2026-10-06.md)
continues the [ratified 15-hour implementation plan](../docs/plans/omux-integrated-delivery-sprint-2026-10-05.md)
without resetting its historical clocks or evidence. The product sequence remains
install/activation, Chromium connection, verified identity and authority,
renewal, ordinary application integration, then same-process handoff proof.
[TIN-5442](https://linear.app/tinyland/issue/TIN-5442) tracks installed-browser
lifecycle and [TIN-5443](https://linear.app/tinyland/issue/TIN-5443) tracks
update/custody scope. Omux implements each application's authentication adapter;
upstream acceptance is required for upstream delivery, not every delivery option.

## Integrated setup and development source

Native UI onboarding uses shared CLI setup/readiness operations. Current source
adds Home Manager fleet exports `homeManagerModules.omux` and
`lib.consumeBazelArtifact` in [flake.nix](../flake.nix), with declarative Linux
packages, isolated instance services and exact-ID Chromium host manifests in
[nix/home-manager.nix](../nix/home-manager.nix). Home Manager owns those objects;
Omux owns runtime custody/enrollment and reports required declarative changes.
Epoch `9fd5966e` passed Nix module-harness evaluation without activation. Later
managed-service definition witnesses remain separate from live service readiness;
the harness does not prove fleet activation or installed readiness.

Declared `//delivery:dev_stage` stages real runtime and development extension
inputs into an owned stable location without a hidden nested build. Reload
Chromium manually and restart the development daemon explicitly. Development
and release use separate identities, services, state, sockets and vault custody.
The development extension's public key is pinned; its extension identity is
`bggghdafplhajiailkafeihemlalagmm`. Epoch `bdbddca6-d527-419e-abdf-4ceef8db710a`
passed development staging predicates with empty descendants. That fixture
does not prove manual Chromium loading or installed development/release coexistence.

Declared `//delivery:chromium_dev_metadata` derives artifact digest, channel,
extension identity and unsigned/proof limits from archive bytes. It requires
explicit `--define=OMUX_SOURCE_COMMIT=<full commit>` and
`--define=OMUX_SOURCE_DIRTY=true|false`; it does not attest source cleanliness or
test compatibility. Epoch `05d7c7e7-29c7-4c24-8099-eb56ac766025` produced the
unsigned development package and its metadata; the overall epoch failed other
targets. Later browser and SPA receipts retain their own scope below.

Actual private-profile Chrome/147.0.7727.116 loading and synthetic recovery
passed in epoch `c8f63b83-f9cb-4233-a01c-5d1e6f30f33d`; the
[Chromium tuple](../docs/tracker-updates/integrated-delivery-chromium-2026-10-05.json)
records health, permission refusal, browser restart and context disconnect.
Human consent, provider acquisition and the complete browser gate remain open.
Epoch `b62de355-e8e5-4c26-a3f6-e4bb8e370f3b` closed the exact local SPA
delivery gate after manifest import, tests, typecheck, build and archive checking.
Its [delivery tuple](../docs/tracker-updates/integrated-delivery-spa-2026-10-05.json)
binds the unsigned development metadata to an unpublished site archive.
`/extensions/dev` renders those selected metadata bytes and limitations; it
supplies no published download. New runtime source or archives require a new
deliberate import and validation chain. Signing and publication remain open.

All executable work uses bounded Nix/Bazel execution. Epoch
`80a8c353-0939-4158-9f73-8a8e926d08c9` qualified host-preserving identity,
cgroup bounds and manager/Nix socket denial with empty descendants;
`bdbddca6-d527-419e-abdf-4ceef8db710a` passed the finite separate-session probe.
Later epochs `e9cf` and `8e61` proved finite cancellation and actual supervisor
output-cap termination with exit 125 and their recorded cleanup predicates.
Failed pre-admission `9e229` retains cleanup=false; its cache remains untouched.
Epoch `120f8b34` passed eleven selected targets with exit 0 and empty descendants,
including cached NAR verification, pinned-Nix comparison and pure authority join.
Exact logs are retained under `delivery/proofs/`. These scoped predicates do not
prove an actual browser, native compilation or universal same-user sandbox.
A shared cache does not replace epoch evidence; earlier failed receipts remain.
See the [integrated receipt](../docs/agent-notes/2026-10-05-sess-omux-integrated-delivery.md)
and [cache retention proposal](../docs/agent-notes/2026-10-05-owned-cache-retention-plan.md).
Historical package and extension receipts retain their own epochs.

Build and inspect a deterministic experimental archive:

```sh
nix develop --command bazelisk build //delivery:release_archive
nix develop --command bazelisk run //delivery:verify -- --verify "$PWD/bazel-bin/delivery/release_archive.tar.gz"
nix develop --command bazelisk test //delivery:delivery_test
nix develop --command bazelisk test //delivery:portable_test //delivery:relocation_test
```

The archive contains `omux`, `omuxd`, and same-bytes `oauth-mux`,
`omux-native-host` and `git-credential-omux` command aliases, plus the versioned
documentation bundle, service templates, a file manifest and SHA256SUMS. Linux
archives also include the genuine Qt `omux-control` tray client and its declared
platform plugins and library closure.
Verification checks every member, payload, mode and
checksum before installation. Archives reject traversal, special files,
duplicates and oversized compressed or decompressed payloads. Generation uses
fixed timestamps, ownership, ordering and compression metadata.

The Linux action copies the exact transitive ELF dependency closure from
declared Nix inputs, relocates each runtime lookup and supplies its own loaders
and public CA bundle. The daemon and Qt controls have separate library trees,
preserving their exact dependency versions across the two processes.
The Linux launcher is a static Zig executable that locates its installation
through a held, verified procfs self descriptor and directly executes the
packaged loader. It creates no child or thread and preserves the actual caller
cwd, raw arguments, unrelated environment entries and inherited descriptors.
It removes loader-injection variables and sets the private runtime paths.
Its canonical loader/role/channel record is appended to the exact template
generated by the declared Bazel action; archive-owned checksums cannot authorize
replacement launcher code. Only the declared native Linux target is available;
foreign target templates fail closed. Other-platform execution is unproved.
Metadata records `portable-linux`. Verification checks every ELF dependency
against that isolated library directory and rejects external lookup paths.
The Qt client has isolated plugin paths and a relative `qt.conf`.
`//delivery:linux_launcher_test` executes the actual compiled launcher with
child creation denied and a recorder in place of its loader. This checks the
exec boundary, including renamed/deleted caller cwd, streams and descriptors,
duplicate raw environment entries, channel conflicts, stack limits and refusal
status with a broken stderr pipe. It does not establish real-loader/backend
continuity. The existing installed and relocation gates retain their assertions.
Development staging still has exec-only shell tiers that replace the original
argv0 spelling; the static launcher preserves the argv0 it actually receives.
The declared `native_runtime_resolution` action runs the original Qt controls
offline to record its effective systemd library selection. Packaging binds
that startup witness to the source binary and every conflicting candidate's
digest, preserves the selected library's complete closure, and rejects other
unrecorded collisions. The archived witness also binds the patched artifacts.
Desktop fonts and XKB resources use the host operating system. Explicit user
service actions use its fixed `/usr/bin/systemctl` interface. The offscreen
startup gate does not establish interactive X11 or Wayland compatibility.

`//delivery:relocation_test` installs the built archive in a fresh path with
spaces and runs its native aliases with no executable search path. It exercises
the Qt client's bounded startup check through its offscreen platform plugin,
native messaging before stdin EOF and verified local HTTPS using an ephemeral
certificate generated during the test. No provider quota or native account
store is accessed. Signing, macOS relocation and live native integration remain
separate gates. A bundle made without the Linux runtime inputs explicitly
records `development-nix-closure-required`.

An explicit development installation records ownership without changing native
application settings or the account database:

```sh
nix develop --command bazelisk run //delivery:install -- \
  --bundle "$PWD/bazel-bin/delivery/release_archive.tar.gz" \
  --prefix "$HOME/.local" --state-dir "$HOME/.local/state/omux-install"
nix develop --command bazelisk run //delivery:uninstall -- \
  --prefix "$HOME/.local" --state-dir "$HOME/.local/state/omux-install"
```

Add an absolute `--user-service` path to install a systemd user service or
launchd agent template. Specify `--platform macos` for a matching macOS bundle.
Installation does not activate the service. Service activation and stopping
are explicit operator actions through the declared platform execution path.
Stop an activated service before removing its installation.

Known-channel portable Linux launchers bind `development` to `OMUX_INSTANCE=dev`
and `release` to `OMUX_INSTANCE=default`. A conflicting explicit instance exits
before executing the backend. Installation uses the matching canonical service
identity. Archives without channel metadata retain their legacy behavior and
remain channel-unknown. Known-channel nonportable packaging is refused until
its launchers implement the same binding; this includes the current Darwin
archive lane. Channel metadata alone never proves installed coexistence.

Existing unowned or modified targets cause installation to fail before
executable writes. The runtime lives below `lib/omux`; installation avoids
placing shared libraries in the general user library directory. Upgrades
require the existing owned bytes and modes to
match; failed writes restore the previous executable contents. Uninstall
removes only matching owned files, retains modified files in the ownership
record, and preserves runtime databases, vault keys, native configuration and
session stores.

The unstamped build archive identifies unversioned, dirty development source.
For artifact-only publication preparation, `//delivery:bundle` accepts explicit
declared inputs and `--source-revision`/`--source-dirty false`; verification with
`--require-publishable` requires a clean full-commit identifier. The caller must
establish that those inputs belong to that revision. This tool does not attest
Git state, sign artifacts, upload releases or publish a website.
