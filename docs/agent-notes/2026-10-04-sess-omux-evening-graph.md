---
title: Omux evening action graph and execution provenance
date: 2026-10-04
status: active
summary: Complete Darwin archive-producer analysis passed the unchanged strict validator after declared C++ and definition-generator environment fixes; remote worker and execution proof remain held.
refs:
  - R-N13
  - R-C227
  - ../decisions/007-local-declared-execution.md
  - ../implementation/native-evening-evidence-2026-10-03.md
---

R-N13 authorizes this durable workstream note and scoped evidence updates under
the existing Omux task. The root reviewed R-C227 and clarified that a product
provenance validator rejecting input data is separate from a managed guard-hook
denial. No hook refusal was bypassed and no process was signaled.

The exact Darwin execution closure remains
`9k958iwyvk7cn5f7axdfg8a0j1s0nsa1-omux-bazel-closure`, with SDK 14.4 and
126 manifest members. Coordinator registration and NAR/reference reconciliation
cover 128 recursive store paths. PZM registration, selected-worker identity,
operator-bound routing and actual Darwin remote actions remain unproved.
Repository bootstrap, receipt platform properties, fresh remote execution,
remote-cache acceptance, artifact bytes and installed behavior are separate
predicates. The helper keeps `worker_routing_verified` false.

The earlier complete graph `972a3df8-9395-4a98-870c-dd7ba4052763` has SHA256
`2ab661030f5cbf0f14b3c11a0ab5873882b24002a98b8e6b8238d1323fe3d032`.
Its final validator `4332c70d-0952-4a7a-bee4-027c80f57f92` rejected an absolute
reference outside the authorized closure. Read-only diagnostic
`7338eaa9-5224-4a38-9ae7-8c6ddcf032f9` identified a product `CppCompile`
executable-search environment reference with an unauthorized, undeclared root.
The locked Nixpkgs Bazel package patches default action PATH to coordinator
utilities. Selected C/C++ features now override it with only the selected
manifest's coreutils directory, already present in declared toolchain files.

Three local smoke analysis failures are preserved separately:
`8e4176bd-3477-4b05-912f-7293d23f016e` rejected an empty C++ `env_entry` value;
`f951ee14-56e3-4a44-a15e-842961d7fd70` rejected private strip API parameters;
`e9deef33-99e6-4c1c-9f3b-eb1011a2b49f` exposed a PIC-only static archive output.
None dispatched compiler actions. Corrected smoke
`fcb9b12b-dc6f-4cdd-ae5f-2a76883bdd0d` passed in 16.021 seconds with five fresh
Linux sandbox actions and three internal actions despite an unusable default
executable search path. It consumed ten configured C/C++ action environments
and tool bindings. C and C++ compilation, executable linking, PIC static
archiving and configured stripping ran; assembly, linkstamp and shared-library
environment checks were analysis-only. Root Linux Qt gate
`db4a0fc4-b715-4d6f-8d73-8f195dadbdc1` separately passed fifteen fresh sandbox
compile/link actions and five matching-cache tests. The preceding C++ epoch build
`05b19b4d-5976-4e53-ab1d-2aa843ae6731` passed 105 targets. Current coherent
suite `cfd57c72-8f91-4c4b-b826-a7316d558d8a` passed 58 tests (four fresh,
54 matching-input cache results), and build
`69c659e4-2e5a-43a3-8c04-33fe9286c6fd` passed all 107 targets. The root
records their exact process counters and scope separately in evening evidence.

Capture `baaa4c50-7b90-441d-b030-e46c6d335acd` queried only the archive target's
own actions. Its SHA256 is
`97d536d146ca2d7188b73e1c4ac9b1c2c00958a3823d1c05d05d6a981fdcd209`
for 48,115,460 private JSON bytes. Validator
`032f2abd-7b7a-44a8-96d2-055ad901d2be` correctly rejected missing required
product producers. Fixed-role diagnostic
`aaafc86c-0574-445e-b075-5b10da3f79ae` confirmed one registered/reachable spawn
and absent control, bundle, CLI and daemon producers. This incomplete capture
does not prove the C++ action fix. A complete query must use
`deps(//clients/macos:archive)` and include response-file metadata.

Complete dependency capture `51c532e0-83fa-4e60-9ac6-7023de3c15a3` passed
analysis in 445.917 seconds with 294,970 configured targets and zero processes.
Its 60,402,573 private JSON bytes have SHA256
`30ffd8535f33c29ea632e3e55dbc7e8b8981750064dec147f1cb2f6a93303300`.
Unchanged validator `8272d592-6175-41aa-a88b-4c17ece7f508` rejected
`absolute reference outside authorized closure`. Sanitized diagnostic
`2f327dfd-4119-4e69-996d-1f6a9474cd44` reported 132 registered actions,
95 reachable actions and twelve checked spawns before an external-tool PATH
rejection. Fixed-role refinement
`99b2e4e1-35d4-4b1c-8e46-bfa81f388fa0` confirmed the pinned `RunBinary`
mnemonic, the owned Arocc definition-generator target, the `generate-def` tool
and its three-argument input/output grammar. No private paths, argument values,
environment values or exception messages were emitted by these diagnostics.

Pinned Skylib 1.9.0 copies `default_shell_env` into `run_binary` and then overlays
its explicit environment. The pinned Arocc generator parses and performs file
I/O in process, without executable search or subprocesses. R-N13 authorized
only the owned Arocc overlay's explicit empty PATH. Generator smoke
`4a269a44-f8f7-4571-a3b6-4e3830f44de9` passed in 118.439 seconds with three
fresh Linux sandbox actions: Zig SDK validation, generator compilation and one
actual definition generation, under an unusable default PATH. This proves one
Linux generator action; additional definitions and Darwin execution remain
separate. Fresh complete dependency analysis
`22e4eb26-c3e7-4219-909b-a535eae467cd` passed on the same isolated Darwin root
in 703.648 seconds, with 294,970 configured targets and zero processes or
dispatched actions. It queried `deps(//clients/macos:archive)` with response-file
metadata, the endpoint-free Darwin profile and the unchanged exact closure.
Read-only metadata receipt `abbbdf18-e648-48e8-8b8e-c24441961774` measured
60,385,833 private JSON bytes. Capture and stderr last-write time was
`2026-10-04T04:21:29.870539+00:00`; completion readback was `04:22:13Z`.

Unchanged strict validator `3ebf9dcc-e8cb-4c22-9c28-0b6d70e971c2` exited zero,
observed at `04:29:14Z`. Its phase is `analysis_only`: 132 registered actions,
95 unique reachable actions, 99 reachable registrations, four duplicate
registrations and 33 unrequested registrations. The archive producer scope
contains 31 spawns (nine product and 22 external-tool actions) and 64 non-spawns.
Required SwiftUI, bundle and archive producers each occur once; the CLI and
daemon have two `ZigBuildExe` producers. The strict absolute-reference and
declared-file checks accepted all reachable spawns without any matcher relaxation
or new authorized root.

The accepted source metadata is the selected `aarch64-darwin` closure, SDK 14.4,
locked Nixpkgs revision `0726a0ecb6d4e08f6adced58726b95db924cef57`, Bazel 9.0.1,
rules_cc 0.2.18, Skylib 1.9.0 and Arocc revision
`d0c8c4d9c55daa7ef6e40cf0f630a5b5e900989b`, with the frozen owned C++ and Arocc
overlays. Fingerprints bind that capture's declared action/input metadata, not
later source edits or executed input contents:

- Graph SHA256: `d4e5299b62ece68797f7dfab9257647501080ce75dc8ab6a937af313f9b12275`.
- Plan SHA256: `15bc1997135a7b0dc4f1c5b1243b31698f2aae9b3951ecb4dff82ddc9573dbc4`.
- Declared-input plan SHA256: `6acfbcc96fa980fd2830cc506ff4092ffb33c662b78c3625e1e2b7d434658f90`.
- Manifest SHA256: `fdfeb78902a8fb28d2e7cff6c4516558c9b0b5e9c4b154b2981a49e561b25087`.
- Store-path list SHA256: `1fb5ca0076bc83a7cc5fb36e73abc4f15a892db8930aa56ff6fc1bbc57e32153`.

Analysis routing, receipt platform-property matching, selected-worker routing,
repository bootstrap, artifact verification and installed proof all remain false.
No execution log was supplied, so complete regular-input content/digest
reconciliation, fresh remote actions and remote-cache acceptance remain unrun.
Earlier loading, inventory, validator and incomplete-query failures remain in
the linked evening evidence. Read-only diagnostic implementation failures
`3c6a69e4-f67b-4117-8bce-7e675b589e09`,
`f788db9f-997c-43c8-b146-d24c7186fe1c` and
`5c781e93-0f8b-4d61-a69b-f82b858135cc` passed strings to a Path-only reader;
`38b6cfaa-a7a2-4d88-87b0-4b4f015b97e4` had a diagnostic-source quoting error.
These failed before useful graph classification and do not constitute graph proof.

The user reports PZM's GF worker held under TIN-2998 and GF#1717, with
`startServices=false`, a dedicated 4 GiB APFS volume, mTLS/JWKS inputs, a shared
operation lock and 168-hour burn-in required before activation. The user also
reports 2.2 GiB free in `/nix`, the 8 GiB ssh-ng builder gate closed, GC running
under R-C256 and the Neo GF fable seat owning the coordinator without an available
operator binding. These are user-attributed operational context, not independent
host observations by this lane. No service, GC, host or other-process action was
authorized or performed here.
