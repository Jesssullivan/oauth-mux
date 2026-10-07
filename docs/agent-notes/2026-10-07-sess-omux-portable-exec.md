# Portable Linux launcher implementation — provider-free continuation

Authority: the user-authorized Omux implementation and provider-free October 6
native/browser checkpoint; repository AGENTS.md; R-HOOK-CONVERGENCE-20261004,
R-N13. Carrier: [TIN-5338](https://linear.app/tinyland/issue/TIN-5338), with
installation [TIN-2063](https://linear.app/tinyland/issue/TIN-2063) and continuity
[TIN-2057](https://linear.app/tinyland/issue/TIN-2057). Product direction remains
[the active reset](../plans/omux-native-account-lifecycle-reset-2026-10-02.md) and
[the continuation](../plans/omux-native-browser-continuation-2026-10-06.md).

## Trigger and bounded change

The source of the previous portable shell launcher demonstrably creates a
child for command substitution before exec. The ordinary 72e0 native test
observed exact completed status JSON and exit zero, but nonempty ASCII stderr
failed its unchanged gate. Whole-workload process samples reached 512 and an
exposed max event increased; they attribute neither stderr nor old incidents.
The earlier 6616 observer failed to fork before executing its status CLI.
[The receipt](../tracker-updates/native-diagnostic-0412-2026-10-07.json) preserves
both failed gates; none proves replay, retirement, preservation or cold resume.

Replace only the portable Linux shell launcher with a fresh static, no-libc
Zig exec trampoline. Bazel generates a trusted template module from the exact
compiled ELF; packaging and verification compare every byte plus the canonical
256-byte loader/role/channel record. Source review required NONBLOCK on owned
opens, held procfs validation, a zero-size GNU_STACK to preserve inherited
stack limits, and terminal-only SIGPIPE masking for fixed refusal status.
No host loader, shell fallback, cap increase, native predicate relaxation,
provider access or session-store mutation is introduced.

## Ownership and reviewed files

Root adopted excluded proposals sequentially into the existing root-owned
`codex/omux-portable-exec-20261007` worktree based on main
`e4e644cd97343d53d3dc08664f5c0914ab173b99` (tree
`bfd67a0dba57a2d03bd3985a994b323ebc0c7b04`, identical to signed #528 source).
The original mixed checkout/index remains outside this adoption.

- Core: `delivery/linux_launcher.zig` and
  `delivery/generate_portable_launcher_template.py`.
- Wiring: `tools/runtime_zig.bzl`, `tools/rules.bzl`, `delivery/BUILD.bazel`,
  `delivery/rules.bzl` and `delivery/portable.py`.
- Meaningful execution/model checks: `delivery/linux_launcher_recorder.c`,
  `delivery/test_linux_launcher.py`, `delivery/test_portable.py` and
  `delivery/test_generate_portable_launcher_template.py`.
- Nested custody bootstrap: retain the virtual runfile path with `.absolute()`
  rather than resolving into physical source. Fresh isolated Python cannot
  inherit its parent's preloaded module. All custody acceptance checks remain.
- Delivery documentation: `delivery/README.md`.

Sol 6.1 core, wiring and test authors proposed separate owned file boundaries;
independent registry and selection reviewers source-cleared the final proposals.
Root is the sole execution coordinator. Source clearance is not execution proof.

## Initial verification order and limits

1. Declared launcher formatting.
2. Generator models, actual compiled launcher predicates, portable archive
   models, docs and source receipt under unchanged aggregate containment.
3. Surrounding declared packaging/staging/import/relocation regression checks.
4. One justified fresh installed native attempt, preserving strict stderr,
   native identity/history, replay, retirement and cold-resume gates.

Initial native template/model execution is Linux x86_64 only. The parser and
generator model both machine types; AArch64/Darwin installed proof remains
unrun. The recorder deliberately replaces the loader and uses a sentinel
backend. It establishes the exec boundary, not genuine backend/native
continuity. Final loader/backend path lookup is not an atomic held-byte
security boundary. FIFO replacement races remain unproved. Existing upstream
development stage shell tiers preserve alias basenames while changing initial
argv0 spelling. No whole-stage shell-free or raw-original-argv0 claim is made.

Yoga's fresh QUAL/INSPECT passed, but VERIFY refused a nonobject registration
row. No closure copy, browser installation, human toolbar consent or native
proof followed. Home Manager offline evaluation remains unproved; PZM/GF is
held. Live providers, accepted history, stock Codex, same-process live handoff,
Darwin, publication and achieved SLA remain outside proved scope. Five scoped
parent passes and six open gates remain; elapsed time closes no gate.

## Execution receipts

Formatter epoch `4e2ab760-1280-4677-b6da-f382b3eef8c2` finished 0/0 with
empty descendants. The new formatter was initially refused before unit start
because the closed guard admitted only prior root formatter tuples. A reviewed
exact standard-only tuple and refusal models admit this one source file without
changing caps or other profiles.

Targeted epoch `77e9da46-31db-4030-b018-63c66e6a427f` finished 3/3, empty,
with six of seven targets passed: compiled static launcher, generator models,
portable archive models, launcher formatting, guard models and source receipt.
The only failure was the new note's missing authority classification; its map
entry is corrected. Whole-workload samples peaked at 345, with no sampled
512 or exposed max-event increase; terminal counters were unavailable. These
sampled observations carry no individual-process or historical attribution.
See [the receipt](../tracker-updates/portable-exec-2026-10-07.json).

Regression epoch `9b69bca2-e259-4cff-b408-adda3b9ced9d` finished 3/3, empty,
with eight of eleven targets passed, including actual portable Omux/Qt/HTTPS
relocation, compiled development staging, direct-exec C fixture, delivery,
private-session process models, corrected docs and source receipt. Three
failures were outdated fixtures: the shared dev-generation valid runtime
omitted required launcher metadata, and the observer invoked Bash on the new
ELF. Reviewed fixture corrections add independently declared metadata, invoke
the ELF directly and retire the unused Bash argument. Their original custody,
tamper, stream and exact FD2 record assertions are unchanged. Failed epochs
remain preserved. Correction epoch `bb7c913f-bb2c-4070-8375-6d9145c24639`
finished 0/0, empty, with all five targets passed: both generation suites,
the observer, docs and source receipt. This closes the fixture correction,
not an installed native acceptance gate.

Installed native/browser gates remain pending; real relocation is not native
continuity or visible browser proof.

Root is preparing a signed source-only delivery after these scoped checks.
Inspected Home Manager Git hooks are advisory under R-N12; per-invocation
`core.hooksPath=/dev/null` avoids duplicate unqualified project/credential
checks. Global hook configuration remains unchanged. The declared aggregate
checks and independent Git signature/head/tree inspection are the traceable
alternative; normal branch push and exact-head reviewed merge remain required.
