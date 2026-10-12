# Omux runtime and enrollment checkpoint — 2026-10-12

Authority: user-authorized integrated implementation, repository AGENTS.md,
R-HOOK-CONVERGENCE-20261004 and R-N13. The original integrated goal remains
active and incomplete; elapsed checkpoint time creates no capability claim.

Current implementation joins owned paired renewal, authenticated quarantine-only
restart recovery, a redacted account-bound model catalog, shared CLI/Qt
first-account enrollment and bounded native-producer refusal diagnostics. These
are Omux-owned integrations; no vendor-provided Omux hook is assumed.

The product remains install/activate, authorize sources once, verify usable
authority and maintain renewal, then use ordinary native applications with
preserved process/history and no accepted-work replay. The optional extension
acquires declared browser data through native messaging; it cannot by itself
supply application continuity.

## Version-bound results

- At `53628c3d`, all 460 original runtime cases passed after durable report
  ordering/duplicate acknowledgement and fixture corrections. The individual
  full-suite budget is 900 seconds inside the unchanged 1,200-second supervisor.
- At `9b0fcc29`, owned renewal compiled and 477/479 runtime cases passed.
  The remaining concurrency expectation and real startup SQL recovery refusal
  were diagnosed and repaired.
- At `947db8ff`, four focused renewal cases passed: same-generation independent
  work with an accepted-work generation-switch fence, stopped issued renewal,
  expired original deadline and unrelated account forget. The original
  authenticated epoch is preserved; recovery never reconstructs a refresh
  ticket or replays a spent refresh credential.
- At `c5ea4936`, eight selected targets passed: storage124, transport174,
  catalog parsing4, native diagnostic38, Qt transport/paths, formatting and
  documentation. Runtime and Qt enrollment/setup had compiler failures.
  These overlapping suites are not unique-case totals.
- At `c447be20`, CLI and Qt control binaries built, setup UI/format/docs passed,
  and the full runtime completed 485/493 with no skipped cases. Seven failures
  stopped in a shared fixture before production; one exposed a real parser
  allocation-failure identity defect. Qt enrollment stopped before handshake
  because the fixture did not establish the required private socket.

The original failed receipts remain immutable. No failed build, incomplete
target or empty XML row is counted as PASS.

## Corrections after the full runtime checkpoint

The catalog dispatcher now handles initial parsing failure at the original
invocation: null JSON-RPC identity, the existing refusal code and original
parser error. It cannot reparse with the reply allocator after actor allocation
failure. The existing allocation gate and assertion remain unchanged.

The shared catalog helper represents only its empty anonymous tuple as the
intended JSON object; other object guards and test assertions retain their
original behavior. The UI fixture uses the same checked private socket setup
as the passing transport fixture. Production peer and socket guards remain.

The current focused catalog target executes the existing actor cases.
No containment, deadline, allocator gate, assertion or test-skip policy changed.

At `baa33e88`, the focused catalog target completed12/13 cases successfully.
The remaining case concerns an in-flight pause and unrelated metadata revision.
The original queued-ingress allocation/identity case passed unchanged. Qt
enrollment advanced to its first cancellation assertion (Exit18); its follow-up
is still open. Format and documentation passed. The full493-case regression
has not passed at this successor and must not inherit the earlier460-case PASS.

## Execution, cleanup and next proof

One coordinator executes through the locked Nix/Bazel graph: 4 GiB memory,
512 tasks, CPU200%, swap0 and an overall1,200-second deadline. Routine checks
reuse the qualified per-checkout output base; other lanes retain separate
receipts and retire their disposable output/user roots after evidence capture.
Explicit R-C618 residual sweeps preserve receipt.json, supervisor.json,
test-evidence* and workload.log. Filesystem-wide space/inode snapshots are
distinct from removed-entry/last-link allocation counters.

The next product gates are installed first-account enrollment with the normal
OS vault, the exact maintained native candidate and ordinary accepted-history
resume, followed by real same-process handoff. The current native source model
PASS does not qualify its genuine Rust producer. Current retained usable-account
counts and normal-vault readiness remain Unknown; earlier one-account removed
fixture evidence retains its original scope.

Unmodified Codex, live handoff and Darwin activation remain unproved. Chromium
human permission proof, extension signing/persistent delivery and publication
remain separate gates. The Linux-only Home Manager guard is retained; Lab's
Darwin signing leg is welcome under the already-recorded requirements.

No live provider calls, production service activation, signing, publication or
merge occurred in this continuation. No achieved SLO or contractual SLA is
claimed. Reliability success and timely safe refusal retain separate scopes.

[PR541](https://github.com/Jesssullivan/oauth-mux/pull/541) remains draft.
[Renewal carrier](https://linear.app/tinyland/issue/TIN-3032),
[installation carrier](https://linear.app/tinyland/issue/TIN-2063) and
[Codex carrier](https://linear.app/tinyland/issue/TIN-5338) retain their completion
states. [Darwin requirements](https://github.com/Jesssullivan/oauth-mux/issues/542#issuecomment-6112773277)
are already answered; signing alone does not establish activation.

## Focused follow-up — CF-1507 at a2d3677b

At exact source `a2d3677b7b7422e7921067821234ffd70fc142d5`, CF-1507
(epoch `be532e4e-ed82-4452-b3e7-cd2e552bbbe6`) completed with outer/workload
exit 0/0. All four declared targets passed: the focused catalog actor's 13 cases,
Qt enrollment/cancellation/recovery fixtures, formatting and documentation.
This closes the focused follow-up at this source; the earlier 12/13 and Exit18
failures remain dated evidence. It does not establish a full 493-case PASS.

The retained raw receipt is SHA256
`ac57d4eec0831744b1018201eed7cb5f2f0bb12ce2f492c6725ea0ebbadfccf7`;
test-evidence manifest
`c2e57fd402d9c75685e23679620a1294ced881a70766573511a2b23829a3b7a6`;
workload log
`b671f5b7933375a8bf0e7532945de06ffa6d17b639599812158b2f4ec3d46ed7`.
Generic cleanup metadata reports empty/unproved with zero ownership readbacks;
cgroup absence alone supplies no owned-cleanup qualification.

The separate finished R-C618 residual sweep for this epoch removed 559,705
entries and 559,705 last-link inodes, with 1,031,372,800 observed allocated bytes.
Its named output-base/user-root removal preserved receipt.json,
supervisor.json, test-evidence* and workload.log. These per-entry counters are
distinct from filesystem-wide net changes under concurrent allocation.
The durable residual result is
`2026-10-12-R-C618-CF1507-residual-result.json`.

As of the retained 15:18:43 UTC readback, FULL-1518
(epoch `b70dd15d-0065-4d3f-a349-8d841cbf69c8`) was LIVE at the same exact
source/graph. Its whole 493-case regression result remains pending here.
No terminal outcome, count or cleanup result is inferred.

### Full runtime terminal follow-up — FULL-1518

At the same exact runtime source and graph, epoch b70dd15d-0065-4d3f-a349-8d841cbf69c8 completed with outer/workload exit 0/0. All 493 runtime cases passed; formatting and documentation also passed. This closes the combined runtime regression at this source. The earlier 485/493 failed receipt remains unchanged.

Raw receipt SHA256 `e361ccfa68a42bc0c1792aa2d9dde49c578fc2ce14ce1aee1ce48e1d0252d602`;
test-evidence manifest `041d11e642fc2cb734fa1598d1f00f3b411af45b42eb9752020c54f420528451`;
workload log `a9c01f656130f645981f576e099c0b8992a283c8d02b177cfd6924a31e8f45a3`.

The three-target ordinary-check invocation reused the qualified per-checkout output base. Its shared base remains working cache; copied per-epoch results retain their own source and target bindings. Runtime-model success does not qualify an installed daemon, normal-vault enrollment, provider acceptance or native continuity.


Focused fixture PASS does not prove installed first-account enrollment,
private-pipe/default-browser navigation, normal OS-vault readiness, current
usable-account counts, provider acceptance or genuine native producer output.
Ordinary native launch/resume, same-process handoff, unmodified Codex and
Darwin activation remain unproved. Signing and publication remain separate.
The original integrated goal is still active, overdue and incomplete; its
clock and existing resource/deadline limits are unchanged.
