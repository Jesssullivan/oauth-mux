# Omux execution incident and estate checkpoint

Recorded at `2026-10-05T02:12:35Z`, with subsequent source-only reconciliation.
Authority: the user's incident report and request to come up for air, review the
estate, priorities and deployment goals; [AGENTS.md](../../AGENTS.md),
R-HOOK-CONVERGENCE-20261004 and R-N11/R-N12/R-N13. This receipt holds execution;
it does not complete the active goal or authorize a new sprint, provider access,
publication, fleet changes or another team's service activation.

## Incident and containment

The user reports a roughly four-hour Sting hang, over40GB memory use and
cluster-wide SSH disruption. Their supplied operator capture identifies six
Bazel actions in root's `omux-bazel9-owner-coordinator-20261004` lane, each with
roughly2,660 recursive Bash ancestors, totaling37.8G in the captured user slice.
The captured example names Bash PID3537258, parent3488404 and cgroup
`tmux-spawn-1ca7f763-b624-4c6d-8722-fbc9361dccd0.scope`, rooted at Bazel's
installed process wrapper. The supplied command stops before the repeated Bash
script/argument tail. These are user/operator observations, not an independently
reconstructed process tree. The operational impact must not be reduced to an
unexplained clock or tool-output gap.

The captured culprit is the Omux coordinator lane. A separate long-running SDK
build was also owned by root and was stopped; stopping it alone does not prove
that the captured Omux recursion was removed.

| Actor | Target/ownership | Reason | Ruling | Prior state | Result |
| --- | --- | --- | --- | --- | --- |
| Root | SDK client PID2464713, UID1000; live argv matched recorded invocation `2b4f062d-b216-4d31-a8d6-0cda7b9524cd` and SDK recovery output root | Cancel root's excessive in-flight SDK build during incident review | R-N11 after actual target/ownership check | Active recorded eight-label invocation | SIGINT; Bazel reported cancellation and exited8, incomplete |
| Root | SDK server PID1259837, UID1000; live argv matched exact recovery output base `f857293521e27a22b6cefdd38c39173f` | Release root's remaining server resources after client cancellation | R-N11 after recheck; no active Java task children observed | Server remained with RSS2,490,712kB and238threads | SIGTERM; later `/proc/1259837` absent |
| Root | Omux coordinator output root and captured PID3537258 | Check whether captured owned work remains live | R-N11 inspection only; no name-based signals | Operator-reported recursive actions | At about02:08Z captured PID absent; bounded exact-output-root/argument scan found no matching live coordinator process; coordinator server pidfile absent |

The last row is a bounded negative observation. It does not prove the absence of
all orphaned Bash descendants, cluster health, SSH recovery or future safe
dispatch. No unrelated or cross-session process was signalled. All known root
execution sessions have finished or been cancelled. No new build, test, package,
SDK import, remote dispatch or service activation follows this checkpoint.

The user's subsequent readback states that they killed PIDs through an
intracluster SSH route, observed4k-plus rapid Bash invocations, and hypothesized
recursion around starting a Bazel server. They do not have the requested exact
script/argument tail and caution that complete RCA may be unavailable. Their
cleanup is operator-reported; root does not claim to have performed or verified
it. The Bazel-server-launch mechanism remains a hypothesis.

## Cause: unresolved exact entry point

Read-only inspection found the captured installed `process-wrapper` has ELF
magic. Stored Omux and host Nix tool wrappers use absolute immutable Nix
interpreters/executables and one `exec`; inspected generated documentation and
Zig validation launchers do not themselves recursively start Bazel. This does
not exonerate their downstream argument selection or inherited startup state.

Bazel's embedded test setup invokes the test once and starts a cleanup watcher.
Its source explicitly describes weaker descendant containment under
process-wrapper than linux-sandbox. The repository has no enforced aggregate
memory or process ceiling. `--jobs=4` cannot bound recursive descendants, compiler
internal threads, linker memory or persistent server memory.

The separate fresh SDK opt/schema batch amplified resource exposure; it is not
an established explanation for the user's Omux Bash chains. The repeated Bash
script basename and nonsecret argument roles are unavailable, so the actual loop
cannot be identified from the retained capture. No speculative source correction
or claim of root-cause resolution
is recorded. Process environments and private account configuration were not
dumped during this audit.

## Actual execution dispositions

| Invocation | Disposition and limits |
| --- | --- |
| `aee5c690-ed23-41eb-8344-3a5bc1fe65dc` | Installed discovery emitted a completion marker, then Bazel TIMEOUT;15,600.3s test time. Failed; no installed gate closes. |
| `2b4f062d-b216-4d31-a8d6-0cda7b9524cd` | SDK eight-label batch cancelled, exit8; elapsed17,623.963s, critical17,572.35s. Individual schema actions returned, but no passing batch, selected artifact or new runtime receipt exists. |
| `6d994597-f522-45cb-aa74-ff0ee1041875` | Two installed fixtures ended exit37, SERVER TERMINATED ABRUPTLY / Socket closed. No installed discovery or Git pass. |

The exact five-hour checkpoint was partial. All eight ND acceptance gates remain
unpassed. The conditional ten-hour checkpoint does not authorize dispatch while
execution is held. The goal remains incomplete; no completion or formal pause
was inferred from the user's check-in request.

## Estate and product direction

The [native lifecycle reset](../plans/omux-native-account-lifecycle-reset-2026-10-02.md)
remains the architecture: authorize sources once and keep using ordinary native
applications, preserving the process, native history, tools and approvals.
Automatic native-owner discovery is not automatic account enrollment. Restart,
prepared fallback, zero-turn metadata and unit tests cannot prove live handoff.

| Estate | Current evidence/state | Next meaningful outcome |
| --- | --- | --- |
| Omux runtime and control | Fresh Zig daemon, typed custody/selection and thin-client work; focused inventory23, engine209, native-request217 and CLI9 passed | Fresh installed default-discovery and qualified-selection PASS with bounded termination and owned cleanup |
| Linux packaging/vault | Earlier packaged daemon, CLI, offscreen Qt and genuine private Secret Service receipts | Current-source installed receipt; actual user-service lifecycle and interactive desktop remain unproved |
| Native interoperability | `4b0fcf36` proves configured provider-free app-server registration/removal, same process and initialized zero-turn history | Ordinary candidate TUI startup, then genuine cold resume with exact native state |
| New Codex status epoch | Two actual local Rust status predicates passed; separate source epoch exists | Identified schema/source/runtime package and real protocol/installed receipts; no staged new runtime yet |
| Native lifetime safety | Source review found an independent runtime retirement race; paginated rename does not materialize zero-turn rollout | Separately reviewed exact-generation retirement barrier; real entrypoint history materialization/resume proof |
| Git HTTPS/GitHub | Scoped helper lane and frozen ordinary-Git fixture; latest installed execution failed | Provider-free installed helper PASS before authorized remote evaluation |
| Darwin/PZM/REAPI | Carrier proposal only; GF worker remains held and GF-owned | Qualified Darwin carrier, Apple SDK/runtime/vault/UI/service evidence after GF prerequisites; no Neo compilation substitution |
| SPA | Separate dirty reference-site worktree; derives API/capability/release facts by digest | Import a verified selected reference bundle after local proof; no publication or support promotion now |
| Tracker | TIN-5421 under TIN-5338 plus exact planning readbacks; two authorized creates | Factual disposition reconciliation; ticket existence is not proof |

Stock Codex remains unsupported (`native_support=false`). Live handoff, accepted
nonempty history and provider evaluation remain unproved. Dedicated labels,
profile paths, permitted actions and usage limits are still pending; no live
calls were made. SLOs remain measurement targets, not achieved reliability,
contractual SLA or staffed support. Historical v0.1.15 release truth stays
separate from the experimental unshipped successor.

The largest product dependency is the native integration hook. An experimental
modified Codex can validate the protocol, but does not establish support for an
ordinary stock installation. The upstream integration path and version-bound
support matrix need an explicit decision before broad deployment. Browser
extensions can supply narrowly authorized observations/imports; they cannot
create a missing native authorization-replacement hook. The generic lifecycle
and scoped Git lane should remain part of the product, so the proof effort does
not silently become an LLM-only Codex-fork project.

Source inspection shows Omux branch `codex/omux-native-reset` at `f5f83c1`, with
a large mixed staged/unstaged/untracked reset, and SPA branch
`feature/native-account-custody-reference` at `72c808b3`, also dirty. These are
working checkpoints, not clean committed release candidates. No staging,
commit, reset, push, pruning, source-archive replacement or worktree deletion
occurred during this incident review. Deliberate legacy deletions and historical
proofs must remain reviewable; cleanup cannot destroy the only copy of work.

## Revised priority and deployment gate

1. Preserve the unresolved loop and investigate retained action records where
   available; complete RCA is not promised. Confirm owned descendants
   and host recovery without signalling unrelated work. Establish an enforceable
   dedicated process-group/cgroup memory, PID and time budget with cancellation
   that covers the server and its descendants. Do not constrain the shared user
   slice or rely on a jobs flag alone. Verify the effective limits before any
   real workload. A full RCA cannot substitute for verified containment, and an
   unavailable RCA cannot justify unbounded dispatch. Build/test/generator
   execution remains locked Nix through Bazel; diagnostics and ownership checks
   remain traceable.
2. Use one coordinator and a single bounded installed default-discovery story
   with prebuilt identified inputs. Fixtures must not recursively invoke build
   dispatchers. Require Bazel PASS, prompt return and exact owned cleanup.
3. Produce the separate status runtime receipt; prove ordinary candidate TUI
   idle/metadata behavior and cold resume as distinct real-entrypoint gates.
   Read-only `/export` materialization is a source-inspected possibility only,
   unrun; do not weaken history predicates to get a green fixture.
4. Address zero-owner first install and exact-generation recovery, then conduct
   dedicated provider/accepted-history/live-handoff evaluation under its own
   resource authorization. Retain Git as the bounded non-LLM lane.

The next deployment target is an isolated Linux evaluation artifact. General
service rollout, stock support, Darwin rollout, live continuity claims and public
download/support promotion remain gated. Another broad sprint is premature until
execution safety and one complete installed user story are demonstrated.

## Durability and verification limit

`root | this incident/estate note, current sprint status prose and subordinate
follow-on execution-state record | user-requested incident check-in and durable
context | R-HOOK-CONVERGENCE-20261004, R-N13, AGENTS/reset | stale in-flight/pending
prose, partial checkpoint | exact failures/cancellation and execution hold
recorded; prior proofs preserved; no runtime edits or new execution`.

This note and its index/classification changes received source readback only.
Closing Bazel documentation checks remain deliberately unrun under the execution
hold. Earlier documentation checks do not validate this new epoch.

## Source-only continuation: fixture completion boundary

The preceding goal turn made authoritative progress by recording actual
cancellation/failure dispositions and reconciling the execution hold. This
continuation keeps the hold and inspects source rather than dispatching work.

Readback of the shared coordinator's installed-discovery `test.log` found the
public `OMUX_INSTALLED_NATIVE_DISCOVERY_OK` line. That shared output path is not
an immutable invocation receipt and supplies no fresh PASS. Source inspection
shows the outer marker requires the private session's successful exit, bounded
pipe drain and unreaped-child anchored group cleanup to have returned. Before
this continuation, it still preceded the outer TemporaryDirectory cleanup.
This narrows a future investigation to temporary-directory removal or remaining
test-runner finalization after the fixture marker; it does not identify the
recursive Bash command or establish the historical stall's location.

Root moved the new discovery fixture's private marker after its `finally`
cleanup, and its public marker after TemporaryDirectory exit. A fixed
`private-context-cleanup` failure phase now distinguishes that final stage. All
custody, native identity, sealed-state, no-effect and exact-exit assertions remain
intact. This changes marker meaning; it is not a fix for the unknown Bash loop.
The preserved installed interoperability fixture, original archives and runtime
epochs were not edited.

`root | delivery/test_installed_native_discovery.py and this receipt | tighten
completion evidence for the authorized installed discovery gate during source-only
incident review | R-HOOK-CONVERGENCE-20261004, R-N13, AGENTS/reset | marker before
final cleanup; source frozen but installed execution failed | marker follows all
fixture cleanup; source readback only, tests unrun, execution held`.

## Source-only continuation: explicit status schema packaging

The preceding continuation made progress by moving the discovery completion
marker after cleanup. This continuation preserves the same execution hold and
reads the saved output of the cancelled SDK batch; it is not a verified wait or
a claim that the server remains active.

In the recovery output base `f857293521e27a22b6cefdd38c39173f`, under
`execroot/_main/bazel-out/owner-linux-opt/bin/bazel/schema/`, the saved
`public-schema-bundle.stable` contains these introduced members:

| Family | Paths relative to the stable bundle |
| --- | --- |
| JSON | `json/v2/OmuxOwnerAttachmentStatusParams.json`, `json/v2/OmuxOwnerAttachmentStatusResponse.json` |
| TypeScript | `typescript/v2/OmuxOwnerAttachmentStatusParams.ts`, `typescript/v2/OmuxOwnerAttachmentStatusResponse.ts`, `typescript/v2/OmuxOwnerAttachmentDisposition.ts`, `typescript/v2/OmuxOwnerNativeRef.ts` |

The params schema rejects additional properties and requires `protocolVersion`
and `threadId`. The response preserves exact generation strings, distinct
registration/detach operation fields and the nullable actual native reference;
its dispositions are unmanaged, pending, unresolved, attached and retired.
This is source/output inspection, not fresh runtime protocol verification.

Those six files are absent from the experimental tree. That is expected:
`selected_outputs` in the declared importer consumes JSON/TypeScript from stable
and only `precomputed/app-server-exports-experimental.json.zst` from experimental.
The new candidate refresh anchor declared the48 baseline introduced paths but
omitted these six. Root added an explicit six-path list to the new package's
refresh arguments. No schema bytes were copied, handwritten, generated,
normalized or imported; no SDK source or old artifact was changed.

`root | integrations/codex-native-recovery-candidate/BUILD.bazel and README.md,
this receipt | fix missing explicit inputs to the authorized status artifact
producer | R-HOOK-CONVERGENCE-20261004, R-N13, AGENTS/reset | baseline introduced
paths only, new artifact unstaged | six observed introduced paths declared;
source readback only, tests/import/package unrun, execution held`.

A fresh scoped producer receipt, actual schema import, complete source/graph
binding, artifact verification, runtime packaging and installed execution remain
required. The cancelled eight-label batch is not promoted to a producer PASS.

## User steering: first product integration, not another infrastructure sprint

The user asks to return to Omux goals/completion and whether Codex or another
OAuth TUI should lead. The current tmux cgroup readback has `memory.max=max`,
`memory.swap.max=max`, `memory.oom.group=0`, `pids.max=356224` and unlimited
`cpu.max`. No dedicated containment entrypoint was implemented or activated
before this steering. Execution safety remains a bounded prerequisite; it must
not replace delivery of the actual account-continuity story.

Primary-source comparison identifies OpenCode as a promising candidate for the
first stock-TUI demonstration. Its [plugin documentation](https://opencode.ai/docs/plugins/)
describes local/global plugins loaded at ordinary startup. The
[v1.18.34 plugin API](https://github.com/anomalyco/opencode/blob/v1.18.34/packages/plugin/src/index.ts)
exposes OAuth auth loaders and session-aware message/header/tool hooks. Its
[same-version provider implementation](https://github.com/anomalyco/opencode/blob/v1.18.34/packages/opencode/src/provider/provider.ts)
passes auth-loader options into provider construction and wraps a custom fetch
for requests. Inference: an Omux-owned local plugin may supply a request-time
adapter without a maintained OpenCode fork or launcher. No plugin has been
implemented, pinned into the build graph, executed or proved; collision with
built-in auth, credential storage, refresh ownership, per-session routing,
accepted-stream handling and resume remain feasibility gates.

Codex remains the current ratified first native integration and active goal.
The [official app-server contract](https://developers.openai.com/codex/app-server)
documents experimental externally supplied ChatGPT tokens, refresh callbacks
and rate-limit observation. Those host-client facilities do not establish
attachment to an ordinarily launched stock TUI or quota-driven cross-account
handoff. Our modified candidate's configured provider-free proof remains useful
and separate; it cannot substitute for that user story.

Recommendation for discussion: a short version-bound OpenCode feasibility
assessment as the potential first stock-TUI end-to-end demonstration; preserve
Codex as a named compatibility target and retain Git HTTPS as the non-LLM lane.
This recommendation does not supersede the reset, change OpenCode's deferred
support classification, complete/redefine the current goal, or authorize an
additional implementation sprint. A changed integration order needs explicit
ratification and coordinated scope/acceptance reconciliation.

The proposed product demonstration is: authorize two compatible dedicated
accounts once; launch the stock TUI normally; complete an accepted turn; make
the active account unavailable at a verified safe request boundary; complete
the next turn through the alternative in the same native session/process;
preserve tools/approvals/history; show accurate account/resource status; then
quit/resume through the native entrypoint and reversibly remove the integration.
No accepted stream or tool execution is replayed. Each predicate needs real
version-bound evidence; one passing demo does not imply arbitrary-provider or
mid-stream support. Structured provider resource APIs precede browser acquisition
where available; extensions remain narrowly authorized acquisition conduits.

## Source-only continuation: genuine provider-free TUI persistence

The previous turn yielded primary-source evidence for the integration-order
discussion and recorded the current unbounded execution context. No OpenCode
implementation or sequencing change was inferred. The active Codex goal remains
intact, with build execution still held.

Inspection of the selected native source confirms that
`tui/src/app/transcript_export.rs::load_export_transcript` reads metadata and
hydrates complete history; the unsupported zero-turn pagination response can
fall back to `thread/read(includeTurns=true)`. In
`app-server/src/request_processors/thread_processor.rs::apply_thread_read_store_fields`,
that loaded paginated path calls `persist_thread` for the existing thread.
The export can then report empty conversation content without writing Markdown.
Rename alone updates metadata and does not establish that original rollout.

Root updated the new ordinary TUI fixture to issue the real `/export` command
before `/rename`, wait for its genuine unnamed zero-turn rollout, and verify the
same native process and exact attachment status. The existing named metadata,
private rollout, root session UUID, no-user/no-tool work, sealed custody,
acknowledged detach, cold-resume history and fresh-incarnation predicates remain.
The fixture neither writes a rollout nor supplies a native response. It does not
require a Markdown file or claim that empty export itself succeeded.

`root | delivery/test_installed_native_tui.py and this receipt | repair the
provider-free ordinary-entrypoint fixture's false rename/persistence assumption |
R-HOOK-CONVERGENCE-20261004, R-N13, AGENTS/reset | rename-only zero-turn rollout
expectation; target unrun and runtime unstaged | genuine native export persistence
path and unchanged-incarnation check added; source readback only, tests unrun,
execution held`.

This is preparation for the original provider-free metadata/cold-resume gate.
It proves no accepted turn, tool/approval preservation, stock support,
same-process account handoff, default first install or daemon-replacement
recovery. The missing selected runtime package and bounded execution context
still prevent installed verification.

## Product review continuation: browser delivery and evaluation candidates

The user identified two Codex evaluation candidates. The existing evaluation
matrix now records only `codex-home` and `codex-startup`; addresses, credentials
and provider identifiers are not retained. Profiles, compatible operations,
permitted tools and finite usage limits remain pending. No source or provider
was accessed and no live call was authorized by this planning update.

Source/evidence readback confirms the optional Chromium/Firefox conduit, local
native host, unsigned Bazel packages and ownership-bound registration fixtures.
Production acquisition field lists remain empty/blocked, and a production page
storage reader is absent. The main product bundle carries the host executable;
extension archives and registration remain separate. Real-browser installation,
store/signing/update delivery and account import remain unproved.

The extension README now distinguishes browser acquisition from native request
handoff and records a proposed development route in the existing SPA at
`omux.xoxd.ai/extensions/dev`, with an optional subdomain redirect. No DNS,
website, store or signing change was made. This does not ratify a new integration
order or promote browser/support claims.

Linear readback identified existing carriers: TIN-2720 for provider acquisition,
TIN-2063 for reversible source setup, TIN-734 for the derived SPA,
TIN-5338/TIN-5421 for Codex availability/discovery and TIN-2057 for the actual
continuity outcome. No issue states, assignments, dates or dependencies were
changed in this review. Discussion remains focused on integration sequence,
the first isolated browser profile and bounded account evaluation intake.

`root | existing extension README, evaluation matrix and this receipt |
reassert product/acquisition/install boundaries after user steering |
R-HOOK-CONVERGENCE-20261004, R-N13, AGENTS/reset | unsigned fixture foundation;
production imports blocked; execution held | source-only documentation update
and tracker readback; no fresh checks, provider access or publication`.

## Factual Linear reconciliation after the incident

Root published result-only comments to TIN-5421
(`5cab95f8-0cd1-4296-b57f-8796638eb3ec`, 2026-10-05T02:52:26.236Z)
and TIN-5338 (`6ceb5d5b-b151-4eb1-92af-907289cb6a12`,
2026-10-05T02:53:07.040Z), within the existing user-requested Omux tracker
reconciliation. Exact body readbacks matched. Issue field comparison found only
the automatic `updatedAt` change; Backlog/Todo states, descriptions, assignments,
dates and returned relationships were preserved. The original parent planning
comment remains present. The earlier two-write planning receipt is unchanged.

The [separate factual receipt](../tracker-updates/native-discovery-incident-2026-10-05.json)
records these two additional mutations and readback checks. It preserves the
failed installed TIMEOUT, cancelled SDK build, missing runtime and unproved
ordinary TUI/resume gates. No acceptance, integration-order change, live access,
publication of product artifacts or new execution was inferred.

## Blocked audit: remaining full-scope execution

The previous goal turn made concrete progress through two factual Linear
comments, exact readbacks and the separate durable receipt. It was not a live
process wait and did not pass an installed gate. Current file readback still
shows no new status candidate manifest, validation/schema-import receipt,
runtime archive or runtime receipt. All eight ND gates remain unpassed.

At 2026-10-05T02:55:18Z the same shared tmux scope reports
`memory.max=30064771072` (28 GiB), `memory.swap.max=max`,
`memory.oom.group=0`, `pids.max=356224`, `cpu.max=max 100000`.
This differs from the earlier unlimited memory readback. Root did not set the
new limit and does not infer exclusive ownership of the shared scope, host
recovery or containment adequate for another recursive workload.

The unresolved safe-execution condition persisted through the schema-input
correction, TUI persistence correction, product/delivery review, Linear result
reconciliation and this audit: more than three consecutive goal turns. Source
repairs and factual reconciliation are retained, but cannot substitute for the
remaining runtime/installed evidence. There is no live owned handle to wait on.

The full discovery/resume goal is therefore recorded as blocked, not complete
or paused. Resume requires a recovered dedicated execution context with verified
aggregate memory, process, time and descendant-cleanup bounds. Then produce the
separate candidate/schema/runtime epoch and execute the original installed
discovery, qualified selection, TUI, cold-resume, zero-owner and custody gates.
The integration-order interview remains pending and does not redefine this
goal. Existing clocks, passing epochs, product claims and provider/platform
holds are preserved. No further workload was launched by the blocked audit.
