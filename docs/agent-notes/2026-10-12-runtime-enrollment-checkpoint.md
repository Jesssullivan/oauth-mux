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
