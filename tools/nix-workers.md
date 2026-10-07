# Provisioning a Bazel remote execution worker

Local builds remain the default. The flake exports the exact native tool closure;
`@omux_nix//:execution_platform` records its CPU, operating system and
`nix_closure` execution property. This property is the immutable closure output's
Nix store basename, which binds the manifest and its transitive derivation inputs.
`@omux_nix//:closure_metadata` exports `native.json`, `store-paths` and Nix
registration metadata for inspection and deployment.

Linux Zig links consume the manifest's exact dynamic loader through
`NIX_ZIG_ROOTOPTS`, before the root module flag, and libc library directories
through trailing `NIX_ZIG_LINKOPTS`. The libc ABI and runtime cannot come from a
worker's host distribution. `runtime_libraries` and `qt_runtime_libraries` expose
separate runtime closures for packaging; `qt_platform_plugins` selects the xcb,
offscreen and available Wayland platform plugins without importing other plugins.

Nix compiler wrappers, ELF runtime paths and Apple install names retain absolute
`/nix/store` references. Before enabling remote execution:

1. Export and copy the complete flake `bazelClosure` to the worker's Nix store,
   preserving its store paths and registration. Copy its transitive closure;
   copying only the manifest, headers or compiler executable is insufficient.
2. Mount those immutable store paths read-only into each execution sandbox and
   expose the manifest's operating system and CPU. Darwin workers additionally
   require the declared, authorized Apple SDK/tool inputs.
3. Advertise the exact `nix_closure` property value on workers containing that
   closure. Workers with a different closure must reject these actions.
4. Configure the desired REAPI executor/cache and select
   `--extra_execution_platforms=@omux_nix//:execution_platform`. Override the
   local defaults with `--spawn_strategy=remote` and
   `--strategy=TestRunner=remote` when executing tests remotely. Keep endpoint
   addresses, credentials and scheduler mappings outside repository configuration.

No target changes are necessary when enabling RBE. A missing closure fails rather
than substituting a worker's ambient compiler, headers or native libraries.
Exporting registration metadata describes the closure; it does not install it or
establish an RBE proof by itself.

## Linux coordinator with Darwin execution

For a macOS-only target graph, `OMUX_BAZEL_CLOSURE` may select the locked Darwin
`bazelClosure` while `OMUX_BAZEL_BOOTSTRAP_CLOSURE` selects the locked Linux
coordinator's separate `bazel-bootstrap-closure`. The development shell supplies
that bootstrap closure by default. The repository rule also accepts explicit
`closure` and `bootstrap_closure` attributes; attributes take precedence over
environment. Its fallback to the execution closure applies only when no separate
bootstrap input is supplied.

Repository inventory runs locally with the bootstrap manifest's Python. Its
manifest must match the coordinator OS and CPU, provide transitive `store-paths`
and registration metadata, and contain its immutable Python output. Missing or
mismatched bootstrap inputs fail; no ambient Python is substituted. This Python
only inventories files: every project action tool and native library continues
to come from the selected execution closure.

Materialize and register the complete Darwin closure in both the coordinator's
and Darwin worker's Nix stores, including the authorized SDK/compiler inputs.
The coordinator needs these files for repository validation and declared-input
enumeration, even though it does not execute Darwin compilers. Preserve the
absolute store paths and mount the worker closure read-only into action sandboxes.
The checked-in `--config=darwin-reapi` profile selects the fixed
`//tools:darwin_aarch64` target and the imported closure's execution platform,
limits dispatch to one job, requests remote execution for actions and tests,
and prohibits local fallback. Add `--config=reapi-proof` when a receipt requires
fresh execution rather than cache acceptance. The profile contains no endpoint,
credentials or lab-specific pool mapping. Supply the execution closure explicitly
with `--repo_env=OMUX_BAZEL_CLOSURE=/nix/store/<locked-darwin-closure>`; the local
shell supplies its separate bootstrap closure. The scheduler must route the exact `nix_closure`
identity to a matching Darwin worker; pool mappings, endpoints and credentials
remain operator configuration. Keep the Bazel host platform on the coordinator.

This is a single Darwin execution graph, not a mixed Linux/Darwin native-library
graph. Verify repository bootstrap, actual action execution, packaging and tests
before recording an RBE receipt. Remote compilation alone does not establish
installed application behavior or same-process native continuity.

# Ownership-sensitive local tests

`TestRunner` uses `processwrapper-sandbox`; build actions use the namespace
sandbox. Linux user namespaces map only the invoking UID, so root-owned path
ancestors appear as the overflow UID. The daemon correctly rejects those
ancestors. Tests instead preserve real UID metadata and create only explicit
temporary fixture stores. This is still a Bazel declared-input/runfiles sandbox;
it does not provide the namespace sandbox's mount or network isolation. Remote
test workers must likewise preserve meaningful current-user and root ownership.
Production ownership checks are unchanged, and no tests enroll personal stores
or invoke providers.

## Bounded exact-closure operator helpers

`//tools:host_closure_transfer` and `//tools:host_route_probe` use the locked
Linux coordinator's `@omux_host` Nix, SSH, Python and Bash tools. They do not
compile on Neo or PZM, modify daemon trust or launchd configuration, read
credential contents, or substitute another execution closure. Transfer pins
the declared tool runfiles before starting, because simultaneous Bazel
configurations can change the checkout's `bazel-bin` alias.

The transfer helper accepts only
`/nix/store/9k958iwyvk7cn5f7axdfg8a0j1s0nsa1-omux-bazel-closure`.
It verifies the three SHA256 values recorded in the
[evening handoff](../docs/implementation/native-safety-evening-handoff-2026-10-03.md)
before copying from the authenticated Neo source. Its 126 declared paths must
match the hash-pinned registration's NAR hashes, NAR sizes and reference edges.
Recursive registration must contain exactly those paths, the closure root and
`y8ymfapxc856x19kgqvj65l9xkfi76iz-closure-info`; unrelated registered paths fail.
The coordinator also recomputes the two additional roots' physical NAR hashes.
PZM completion requires all 126 physical members and the identical coordinator
and PZM registration identity, including reference edges.

Modes `inspect`, `inspect-pzm`, `protocol-neo` and `protocol-pzm` are read-only. The protocol
mode reports remote-store connectivity and current-client trust as booleans,
plus bounded public Nix version metadata. It does not infer wire compatibility
from matching release numbers. `pull-neo` and `push-pzm` copy the single fixed
recursive closure. Their user-authorized per-copy `--no-check-sigs` exception
admits locally built unsigned outputs over the existing authenticated SSH
route. Nix NAR/store validation remains enabled; no global signature or trust
setting changes. A destination that reports an untrusted client fails before
the unsigned push. This exception supplies no signature provenance.

Coordinator receipt `26a1451c-fbf8-4521-96da-83ac0edb8c10` reconciled 128 exact
registered paths, all 126 physical declared members and 3,151,018,144 NAR bytes.
Its reference-sensitive registration identity is
`d7461660b5fc1c5639dd96e0aaa096ea8ad88499846cb32c87a0a5a5593cbd89`.
The composite PZM push failed; that receipt proves only its successful
coordinator predicates. Earlier signature-policy failures and the unsigned
exception are separate evidence, not a successful PZM transfer receipt.

Both helpers bound stdout and stderr while reading, own and terminate their
local process groups, and restore interruption handlers. They emit closed error
categories and boolean diagnostic hints; raw stderr, endpoints, credentials
and operator environment values are discarded. The route helper observes only
fixed service labels, socket/listener presence, fixed credential-file presence
and fixed variable presence. An unobserved listener or missing variable in this
context does not establish absence of every operator lane.

Closure materialization and Nix-store registration do not establish a registered
REAPI worker, scheduler routing, fresh remote actions, an archive, installation,
or native continuity. These helpers always report worker routing as unproved.
Actual Darwin actions still require the exact `nix_closure` route and a separately
bound executor/cache/instance/auth context. The observed PZM SSH-ng/tool-route
failure does not establish global REAPI unavailability.

Read-only discriminator `b5c21e56-8e94-41a8-bfdf-e0b0c7eec6f0` still reported
PZM store transport failure with noninteractive SSH and per-invocation connection
multiplexing disabled. Baseline `6b4fb6f5-85e7-4bd0-b0df-73d187c59a7d` connected
to Neo's store and reported the current client trusted. Both hosts reported Nix
2.35.2 against coordinator Nix 2.34.6, so that version difference alone does not
explain the observed PZM failure. Neither discriminator copied store paths or
proved a REAPI route. PZM's supported immutable remote-store entrypoint or
operator route remains to be established before another copy attempt.

`local-daemon-pzm` compares that failed SSH-ng route with PZM's local daemon
using the exact immutable sibling `nix` CLI resolved from the same daemon alias.
It runs the documented read-only
[`store info --json --store daemon`](https://manual.determinate.systems/command-ref/new-cli/nix3-store-info.html)
and emits only connectivity and client-trust booleans. Original comparison
`3bdc1968-f0e7-46cf-8bfd-ac8b74b9a85f` could not produce the required metadata.
Refined receipt `a8997494-e012-4aab-8a41-9f9802d0cc46` established that the older
`store ping --json` invocation exited zero with empty stdout; the helper reported
`local-daemon-response-framing` rather than claiming trusted-client metadata.
This silent result is consistent with the documented
[`store ping`](https://nix.dev/manual/nix/2.27/command-ref/new-cli/nix3-store-ping.html)
behavior, so it does not establish daemon failure. The earlier receipt remains
a failed helper result; it is not rewritten as a trust or remote-route proof.
Documented local `store info` comparison
`652c5208-08a5-4cac-9a16-82d9f9167f05` likewise exited zero with empty stdout,
leaving its required client-trust metadata unproved. `coordinator-info` checks
the declared coordinator CLI's `store info` support and local daemon trust
metadata without SSH. These comparisons neither alter the daemon nor replace
the separate SSH-ng route-readiness requirement.

The fixed route probe also reports whether `NIX_GET_COMPLETIONS` is set, using
`${NIX_GET_COMPLETIONS+x}` without reading its value. Public Nix CLI source
describes a completion path that returns before running the selected command.
Presence alone can be consistent with that mechanism; it cannot establish the
cause of an empty response. The probe never changes the remote environment.
Coordinator command receipt `8931ce6c-dae7-402e-a074-942378a599fb` separately
passed declared Nix 2.34.6 `store info` JSON support and local daemon connectivity
with current-client trust. It supplies no PZM route or trust claim.
