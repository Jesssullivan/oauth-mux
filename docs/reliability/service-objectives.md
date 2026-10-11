# Native service reliability objectives

Status: adopted design and measurement targets for the experimental, unshipped
native reset, ratified in the user-authorized design review. These targets require
instrumentation and workload calibration before achievement can be measured.
Omux is self-hosted per-user software. There is **no present contractual SLA,
managed service, staffed response commitment or service-credit entitlement**.
The targets below are not measured results or promises. Historical v0.1.15
evidence does not establish successor reliability. Authority remains the
[reset](../plans/omux-native-account-lifecycle-reset-2026-10-02.md),
[reset evidence](../implementation/native-reset-evidence-2026-10-02.md),
[current safety evidence](../implementation/native-safety-evidence-2026-10-03.md)
and source; operational handling is in the [native runbook](../runbooks/native-operations.md).

## Measurement contract

Measure each OS/version, architecture, artifact digest, Omux commit and adapter /
exact native application version separately. Never pool Linux fixture results
with macOS operation or unmodified Codex with an Omux-developed adapter candidate. Promotion requires
ordinary launch/resume, same-process handoff, native state preservation and live
provider evidence; [the capability catalog](../../src/catalog.zig) currently has
no `live_proven` capability. Isolated genuine Linux vault IO, private macOS
Keychain driver IO and installed Linux daemon/Qt predicates have passing receipts.
Personal-session custody, service activation, production Darwin runtime and
live continuity require separate gates;
none establishes an observed availability baseline.

Use current-and-previous-27 UTC-day windows, daily reviews and an incident ledger. Report good,
bad, excluded and unobserved denominators, percentiles, sample counts and strata.
Zero opportunities means unmeasured, never 100%. Fewer than 100 opportunities
means provisional. Record host sleep and explicit operator shutdown separately;
exclude them only from daemon availability while still reporting user impact.
Daemon crashes, lockouts and queue exhaustion during intended operation count
as failures. Provider outages and expired authorization are classified causes,
not silently excluded from end-to-end usability. Missing compatible accounts
are measured in readiness coverage even when excluded from eligible handoff.

| Stable acceptance ID | SLI and denominator | Adopted SLO target and error budget |
| --- | --- | --- |
| REL-001 | Good local control samples / scheduled samples while the host is awake and daemon operation is intended. Good means authenticated, protocol-compatible snapshot within 2 s with `custody_available=true`; no valid grant is needed. | 99.9%; bad budget 0.1% of samples, equivalent to 40.32 minutes in 28 continuously observed days. Missing scheduled observations are unobserved and block promotion. |
| REL-002 | Safe-boundary admission requests with a verified native hook, independently valid compatible alternative, known required provider capacity and durable local admission/completion headroom; numerator completes admission within 2 s. Separately report ready eligible requests / all supported user demands and each ineligibility reason. | 99.9% eligible admission; 0.1% bad opportunities. Readiness coverage target 99%, with authorization, entitlement, provider capacity, local metadata admission and native-hook causes shown separately. |
| REL-003 | Routine eligible handoffs preserving process identity, native transcript/history, tools and approvals, without a routine authorization prompt / all eligible handoff opportunities. | 100% integrity; zero budget for process restart, routine prompt, native state loss, replay of an accepted stream or repeated tool execution. Never waive these through another SLO's budget. |
| REL-004 | Grant insert/renewal/restore/forget operations satisfying encrypted-before-write, OS-vault custody, one renewal writer, generation fences and tombstones / all observed custody operations. Forget commits deletion, all applicable source tombstones and durable completion atomically; local admission refusal preserves retained secrets and previous tombstones. | 100%; zero budget. Fail closed and stop promotion on any breach; no plaintext or replacement-key recovery allowance. |
| REL-005 | Authorized, supported acquisition attempts reaching verified enrollment or a truthful actionable terminal state within 30 s, excluding time awaiting explicit provider/user action / attempts. Report total elapsed time too. | 99%; 1% bad attempts. Ambiguous identities must quarantine; speed never overrides verification or adoption authority. |
| REL-006 | Required capacity observations fresh at demand time / demand-time observation checks, grouped by exact resource, units, scope, bucket and window. Unknown/stale remains visible. | 99%; 1% freshness misses. Target age ceiling 120 s where the reader declares that ceiling, bounded further by provider window/expiry. No extrapolated quota or duplicate shared buckets. |
| REL-007 | Supported install/remove/reconciliation operations ending in verified owned state or safe actionable refusal within 30 s of local work / attempts. Report successful restoration separately from safe refusal. | 99%; 1% timing-miss budget only; zero budget for any unsafe outcome, including overwriting unowned edits, deleting sessions or losing custody. Daemon recovery target within 60 s after prerequisites are restored; no application restart as handoff recovery. |
| REL-008 | Scheduled local health observations with usable redacted metadata and an outcome classification / scheduled observations. | 99%; 1% missing observations. Secret or PII disclosure has zero budget. |

The REL-005 and REL-007 objectives retain their adopted timing targets. Their timely terminal
outcome numerator includes safe refusals; it must never be presented as successful
enrollment, installation or restoration. Export successful user outcomes,
timely safe refusals, late outcomes, cancellations and unresolved outcomes
separately. A fast refusal improves only the response-time measure.

## Installed lifecycle measurements

The following acceptance amendments are adopted measurement requirements, not
implemented instrumentation or achieved targets. REL-001 through REL-008 and
their zero-budget invariants remain unchanged. Do not invent numerical success
targets for new phases before obtaining a version-bound baseline.

| ID | Phase and successful user outcome | Denominator and coverage |
| --- | --- | --- |
| REL-013 | Install and activate: owned artifacts, service and host registration verified; daemon remains resident after controls close. | All authorized supported installation attempts, including managed-ownership refusal; report installed and activated coverage separately. |
| REL-014 | Connect and enroll: selected browser context authorized, provider identity verified and usable authority recorded with truthful binding and renewal ownership. | All supported authorized connection/enrollment attempts; report connected, verified identity and usable-grant coverage separately. Browser consent alone is not API authority. |
| REL-015 | Renew: the sole authorized writer commits a verified successor generation before authority expires, without replay or ambiguous rotation. | All renewal opportunities for adopted renewable grants; report unavailable external writer, browser-required grants and expired authority as readiness causes. Imports never imply writer transfer. |
| REL-016 | Ordinary launch/resume and handoff: the exact adapted application launches or resumes through its native flow and successfully admits work; handoff additionally satisfies REL-003. | All supported user launch/resume demands; report application/version adapter readiness and eligible handoff coverage separately. Candidate and delivered adapter evidence remain distinct. |
| REL-017 | Update: compatible owned artifacts activate through the declared deployment lane while custody generations, tombstones, accepted work and replay authority remain intact. | All authorized supported update attempts, including compatibility or declarative-ownership refusals; report activation and rollback outcomes separately. |
| REL-018 | Disconnect/remove: the requested context or owned installation is detached/removed with its explicit retention policy satisfied and independent grants/native history preserved. | All authorized supported lifecycle removal attempts; distinguish source detachment, secret removal, identity forget, upstream revoke and package removal. |
| REL-019 | Durable baseline: phase and end-to-end outcome measurements survive restart and identify exact deployment/application provenance. | Scheduled observations and all lifecycle attempts; missing, excluded and unobserved coverage is explicit and prevents promotion. |

Each attempt needs an opaque operation correlation, phase, terminal outcome,
typed cause, monotonic local-work duration, end-to-end elapsed duration and
explicit user/provider wait duration. Start end-to-end timing at the user's
request and finish only at the verified outcome or classified refusal; retain
elapsed time across restart without confusing wall-clock changes with work
latency. A success is a completed user outcome, not a returned operation ID,
healthy transport, configuration write or candidate fixture. Record phase
coverage and supported-demand readiness alongside percentiles and success
ratios; do not omit missing prerequisites to improve end-to-end success.

Persist only bounded, redacted measurement facts with artifact digest, commit,
OS/architecture, channel, adapter revision and exact native application version.
Measurement retention must not reset credential generations, tombstones or
request authority. The existing in-memory diagnostic export is not this durable
baseline. Baseline receipts identify workload, sample counts, observation window,
outcome definitions and unrun gates before any achieved-SLO or support claim.

The source-only resident REL-016 collector now defines one observation for each
selected admitted resident evaluation attempt in the existing immutable guard
receipt: [collector](../../tools/execution_guard.py),
[producer and strict reader](../../tools/guard_resident_continuity_profile.py).
Success requires the actual native/resident proof and successful outer exit,
source readback and empty owned cleanup; admitted failure and unresolved
cleanup/controller states remain separate. No safe pre-effect refusal is
inferred. Stored elapsed time covers only the original same-guardian monotonic
entry-to-terminal interval before receipt writing, and survives receipt reread
without subtracting a new process clock. User elapsed, local work, user/provider
wait, pre-admission refusals, complete supported-demand/lifecycle coverage and
scheduled baseline remain unmeasured. Source/models and actual outcomes remain
unqualified; this closes no full REL gate and establishes no achieved SLO/SLA.

Implementation trace: [TIN-2063](https://linear.app/tinyland/issue/TIN-2063) owns
installation/readiness, [TIN-2720](https://linear.app/tinyland/issue/TIN-2720) owns
browser acquisition, [TIN-5338](https://linear.app/tinyland/issue/TIN-5338) and
[TIN-5421](https://linear.app/tinyland/issue/TIN-5421) own Codex adapter proof, and
[TIN-2057](https://linear.app/tinyland/issue/TIN-2057) owns continuity acceptance.
These are planning carriers, not evidence of completion.

The timing targets need instrumentation and workload calibration; they do not
describe existing timer guarantees. [Daemon transport](../../src/daemon.zig)
has a 15 s request deadline, 8 s browser frame deadline, 1 MiB frames,
browser/adapter queues of eight and 4/4/8 control/browser/adapter workers.
Controls admit at most twelve connections including four concurrently serviced
connections, with a reserved twelve-slot queue. Incomplete control reads yield
after a 100 ms slice without resetting the absolute request deadline, and a
complete request yields after its reply. A blocked reply still holds its worker
until the socket deadline. These are source bounds, not measured latency. The
[single writer](../../src/engine.zig) has a 32-invocation queue, returns
`ServiceBusy` on saturation and retains a request until actor completion.
A client timeout is not proof a mutation failed. Native work uses its caller
deadline, with a 13 s fallback. These bounds are not a 2 s latency measurement.

The private [persisted snapshot](../../src/storage.zig) has a 16 MiB bound;
the public daemon/control transport above has a separate 1 MiB frame bound.
A valid private checkpoint does not establish that every public snapshot
projection can be returned over that transport. Bounded diagnostics, public
snapshot delivery and any future pagination require their own implementation
and measurements.

Local admission acceptance requires the complete persisted envelope, durable
request/mutation authority and reserved future outcomes to fit together.
Healthy custody, a ready grant and remaining space in an individual ledger
partition do not establish that headroom. Classify local metadata byte or
cardinality refusal separately from provider quota, unknown observations and
vault unavailability. Already-admitted terminal outcomes must remain
completable under pressure using reserved space; releasing unused space cannot
replenish the original request attempt budget or authorize accepted-work replay.
These are desired predicates, not achieved SLOs or installed-client guarantees.

[Capacity polling](../../src/observer.zig) admits at most 16 pending reads,
tracks at most 1024 accounts, spaces polls by 60 s, uses 10 s fetch timeouts
and declares 120 s freshness. Source polling is spaced by 60 s in the actor.
Neither timer promises a completed observation under load. Failed reads retain
only the prior observation until its own expiry; unknown never means ready.

## Budgets, incidents and support agreements

The current source adds optional disconnect timing to the existing
`mutation_authority.Record`, exposed through
`reliability.lifecycle.source_disconnect_timing`. Its process-local interval
starts at actor admission and stops immediately after the original terminal
SQLite commit returns. An optional second authenticated commit retains the
measurement; it advances the snapshot revision once more while preserving the
original outcome revision, cached result and effect authority. Clients refresh
the current revision before another mutation. Replay and restart never start a
new clock or repeat the effect. Missing timing remains missing coverage.

Timing admission prepays the complete encoded witness within ledger and
whole-envelope bounds. Lack of optional capacity leaves timing absent and
preserves source removal. A measurement-preparation failure preserves original
success; an actual later Store failure also preserves original completion but
poisons custody until recovery. Startup validates explicit raw witness fields,
the completed record/result binding and authenticated SQL revision before
storage recovery writes. The legacy no-revision decoder refuses witness-bearing
rows. Older readers may reject the new optional record fields; downgrade must
not discard those fields or restore earlier credential/replay authority.

The projection reports all retained records without a time window. The current
schema2 source measures daemon-owned local work from optional timing admission
through the original committed outcome, plus authorized control-handler entry
through that commit. Handler timing begins after ingress parsing; it excludes
socket framing and complete user latency. Historical schema1 intervals remain
unknown. External user/provider wait, deployment provenance, full demand
coverage, end-to-end latency and achieved SLO remain unknown or unproved.

Setup-verification schema2 adds observed admission-to-terminal-before-commit
duration to safe refusals and collection timeouts. Successful verification and
safe refusal retain separate counters and latency populations; a timely refusal
does not establish installation or enrollment success. Original immutable
results preserve these measurements across replay and restart. Unknown clocks
remain unknown. CLI and Qt readers accept the versioned result without treating
unknown phases as readiness. These source changes require their own current
runtime and installed receipts; the historical passes below do not qualify them.
Epoch `8229cb7a-d9d1-4d53-b2e6-793cddfd7cb9` passed 27 helper/ledger predicates
and all 247 actor/imported predicates, including the five real actor/SQLite
timing cases. The overall batch failed separately on storage declaration,
documentation classification and retained-candidate cold resume; descendants
were empty. See [the scoped receipt](../tracker-updates/integrated-delivery-8229-2026-10-06.json).
These isolated results establish neither complete lifecycle coverage nor a
deployment baseline, and do not close ID-RELIABILITY or REL-019.

Terminal-removal accounting is a [projection](../../src/terminal_removal.zig) of
retained mutation authority, now additively exposed as
`reliability.lifecycle.terminal_removal` without new authority, persisted schema
or wire method. The historical sixteen pure predicates passed in `ecbadbac`.
Epoch `8debe108-b689-4500-9b85-91ed0f77f3ba` passed 250 terminal-removal target
cases, including eight local removal/imported engine cases, plus formatting;
controller/workload exits were zero and descendants empty. Graph SHA256:
`70687d4195d0973b07655b5f3a9c3ba72aee8cd4fe1cf6013e893ecb8bcd5035`;
evidence SHA256:
`c0a777b8798ffc1d4d5f0a375c0826f185032e70e188723185f93dbae100734d`.
See the [resume ledger](../tracker-updates/integrated-delivery-resume-2026-10-05.json)
and [session record](../agent-notes/2026-10-05-sess-omux-integrated-delivery.md).
Actor forget/replay/restart and SQLite-denied admission, synthetic socket-native
remove/replay/restart and lost-detach-reply pending custody passed. Admission
failure is not final-commit-only failure; synthetic socket removal is not live
application removal. Prior `ba695349` remains overall failed on native fixture
IDs despite passing engine 242, collector 39 and formatting targets.
Completed forget/removal, pending safe removal and unresolved authority remain
distinct. Pending is not success; complete denominator, time window, duration
and achieved SLO remain absent. Five product gates pass and six remain open.

For ratio SLOs, budget is `(1 - target) * opportunities`; latency misses count
once per opportunity. Review when more than 25% of a budget burns in 24 hours
or its projected 28-day burn exceeds 100%. Exhaustion pauses promotion and
nonessential changes in the affected stratum until the cause is fixed and
verified. Integrity/security breaches trigger immediate containment regardless
of budget. Observability loss prevents a reliability assertion; it is not an
exclusion mechanism.

The S0–S3 severity classification below is adopted for incident measurement and
triage. Its numerical response, update and recovery times remain proposed terms
for a future staffed support agreement; ratification creates no current on-call
coverage or contractual obligation.

| Adopted severity | Trigger | Proposed staffed-agreement response / updates / recovery objective |
| --- | --- | --- |
| S0 | Secret disclosure, custody corruption, accepted-stream replay, duplicate tool execution or native state loss | Acknowledge within 15 min; updates every 30 min; containment within 1 h. Safe restoration is evidence-dependent and cannot be promised by replay. |
| S1 | Daemon unavailable or all supported admissions blocked with otherwise valid prerequisites | Acknowledge within 1 h; updates every 2 h; restore local service within 4 h after prerequisites are available. |
| S2 | One adapter/source impaired, freshness degraded, installation/restoration blocked safely | Acknowledge within 1 business day; daily updates; mitigation target 3 business days. |
| S3 | Documentation, unsupported version, feature request or cosmetic issue | Acknowledge within 3 business days; agreed disposition within 10 business days. |

These are proposed response and recovery objectives, **not current support
coverage or guaranteed resolution times**. Self-hosted users control their host,
vault, provider accounts and service activation. Any future signed support SLA
must name a supported artifact/platform/native version, coverage hours/timezone,
contact route, owner, measurement authority, exclusions, remedies and escalation.
Only strata with platform/vault/install proof, exact adapter live evidence and
an observed baseline are eligible for such an agreement. Provider availability,
account entitlement and upstream revocation cannot be guaranteed by Omux.

## Evidence and remaining acceptance

New explicit setup-verification source is independently reviewed. Scoped Linux
passes include engine 228 cases and Qt transport 13/setup UI in `33452a55`, and
CLI 16, Qt transport/setup UI, verification 28 and collector 33 in `08581f31`.
The latter overall batch failed; passing targets do not close failed gates.
Latest experimental Linux epoch `ef255a3e-8d6d-4bb7-a044-d9a42e20aded`
passed all twelve targets with controller/workload exit zero and empty descendants:
live self-image observation, collector hardlink recheck, engine timeout/refusal
classification, stalled-service C bridge, CLI 16, full Qt installed custody with
third-restart sealed replay and paired core/browser registration. Exact source/
artifact tuple is in the [installed setup receipt](../tracker-updates/integrated-delivery-installed-setup-2026-10-05.json).
This proves the recorded experimental Linux setup/channel predicates; Darwin/Swift
remain unrun. Actual pinned Chromium in a private profile passed bounded
synthetic service-recovery predicates in `c8f63b83-f9cb-4233-a01c-5d1e6f30f33d`
with exit zero, empty descendants and marker
`OMUX_INSTALLED_CHROMIUM_SYNTHETIC_SERVICE_RECOVERY_OK`. The
[exact Chromium tuple](../tracker-updates/integrated-delivery-chromium-2026-10-05.json)
records health, no-permission/tab boundaries, synthetic pending metadata,
original-ID recovery across browser restart, distinct disconnect and preservation
of independent sources. Toolbar consent, granted permission, provider acquisition
and native continuity remain false. Exact-generation daemon restart passed in
`fb13c1ae`; the [restart tuple](../tracker-updates/integrated-delivery-restart-2026-10-05.json)
retains its two-start scope. Committed lost-reply recovery and manual Chromium
reload/reconnect joined to that generation are not proved; full browser
acceptance remains open. See scoped epochs in the
[resume ledger](../tracker-updates/integrated-delivery-resume-2026-10-05.json)
and [session record](../agent-notes/2026-10-05-sess-omux-integrated-delivery.md).
Earlier receipts retain their own byte scope. These passes do not establish
reliability end-to-end timing, coverage, an achieved SLO or SLA. `omux setup verify` requests identified
`setup.refresh` with `operation_id` and `expected_revision`; empty refresh remains
an unmeasured diagnostic. Existing external mutation authority durably records
started state and prepays terminal space before worker execution. Exact replay
returns the cached result; changed intent conflicts. Busy or missing installation
selection is a classified safe refusal. Collection timeout records immutable
`safe_refusal` / `collection_timed_out` and seven unknown phase facts. Historical
schema1 refusals retain null duration; current schema2 source may retain an
observed process-local admission-to-terminal-before-commit duration, with missing
duration remaining null. Refusal counters and latency populations remain separate
from verification completion; optional timing establishes neither successful
installation/enrollment nor complete coverage or an achieved SLO.
Shutdown/restart uncertainty never
authorizes reissue; query `operation.status` using the same ID.

[Setup verification facts](../../src/setup_verification.zig) contain seven fixed
phase reason/outcome pairs: artifact, service, vault, source, identity, grant and
native. `verification_completed` means local checks completed, not installation,
enrollment or handoff success. Outcomes are `verified_ready`, `action_required`
or `unknown`. Timing is process-local admission-to-terminal before commit only.
`reliability.lifecycle.setup_verification` derives its bounded summary from
immutable results in the existing 4096-entry mutation ledger, with no new ledger,
persisted field or migration. Started/indeterminate uncertainty, old-window,
future-clock and missing-timing records remain visible. Empty refresh/passive
polls add no attempts. No end-to-end latency, coverage baseline, achieved SLO or
SLA is established by this source.
Joint-readiness projection passed `//:reliability_readiness_test` in `c5d684a2`:
248 cases (six new and 242 imported), plus setup-verification, docs and source
capture targets. The fourteen-target batch exited 3 with empty descendants;
two Yoga launch-fixture lifecycle errors remained, so it is not an overall pass.
Evidence SHA256: `61add2fb2a93757203a76881c64f6bfd9194ec8fc3c166a296e5a6fe94085bb1`.
Completed retained verification facts receive one
exclusive classification: any action-required phase wins, otherwise any unknown
phase wins, otherwise all seven are ready. `unknown_phase_present` overlaps those
classes to retain uncertainty. Refused, unresolved, old-window and future facts
do not enter joint counts; replay introduces no new sample. Six passing new
[predicates](../../src/reliability_readiness_tests.zig) include owned-environment
engine collection with owned environment/missing receipt, replay and SQLite
restart. Pure all-ready is a projection fixture;
the actual collection correctly expects zero all-ready because native readiness
has no current producer. `complete_user_demand_denominator=false` and
`installation_success_measured=false` remain explicit. This adds no setup-success,
coverage, SLO or acceptance-gate promotion.

Applied local runtime selection measures owned installed files and binds their
digests to channel, registry transaction, adapter epoch and actor revision.
These are authenticated actor metadata stored as snapshot JSON TEXT; grant
payloads remain ciphertext. This measurement does not attest original source/
artifact provenance, a running backend, usable authorization or native readiness.
It supplies neither a lifecycle opportunity nor successful launch/handoff proof;
the seven-phase native readiness fact remains unknown.

The applied registered-owner removal fixture now induces actual optional
post-terminal allocation failure and requires successful removal, verified
detach, original configuration and exact-once replay/restart. It replaces a
never-passing physical-envelope sweep that combined near-16-MiB snapshot work
with failures at the unchanged native deadline. Failed receipts remain preserved; registered
physical-capacity margins remain unproved. Zero-owner physical-pressure evidence
retains its independent scope. The corrected fixture and measured-runtime source
require their own passing receipts; neither adds demand coverage, an observed
baseline or achieved SLO/SLA.

Current experimental gates AUTHORITY, CONTAINMENT, CHANNEL, SETUP and DELIVERY
pass their bounded predicates. Local SPA import/render/archive passed in `b62`;
the [exact SPA tuple](../tracker-updates/integrated-delivery-spa-2026-10-05.json)
remains unsigned and unpublished. Foundation epoch `9fc` failed overall despite
20 browser-root, 18 acquired-source, 63 setup and actual selected-stage passes;
the corrected 27-selector predicates passed in `d4fb`, recorded in the
[selector receipt](../tracker-updates/integrated-delivery-selector-2026-10-05.json).
These installation/delivery predicates do not supply an observed reliability
baseline or promote enrollment/native/live continuity.
Native dependency producer `0ebaff4d` passed its first 16 actual SDK objects with
exit zero and empty descendants; its dated tuple recorded 1,420 missing objects.
The later [verified native union](../tracker-updates/integrated-delivery-native-union-2026-10-05.json)
contains 305 unique verified objects, with 1,410 missing and 42 unresolved
dependencies. This is acquisition evidence, not compilation closure/native proof.
Rerun `bd412392` was rejected with controller/workload 125 and unproved cleanup;
its apparent test passes are unadmitted and promote no historical receipt or gate.
Setup artifact collection observes backing-file mapping identity diagnostically;
it does not attest executable memory or native application identity. A matched
backing file does not prove installation, activation or native continuity.

REL-009: `system.health` and `reliability.export` inspect local metadata without
provider IO. The bounded in-memory recorder exports typed counters, latency
buckets and causes for the current and previous 27 UTC days. Diagnostic export
schema v2 includes timed good/bad opportunities only, counts missing latency,
and distinguishes unmeasured percentiles, finite inclusive bucket bounds and
values above the largest 60-second bucket. Excluded and unobserved work does
not contribute timing samples. Cause labels include `local_capacity` for local
metadata byte/cardinality limits and `result_bound` for bounded result limits.
These additive schema v2 labels preserve existing cause indices. Consumers must
map each counter vector using the exported ordered cause names and vector width;
schema v2 makes no fixed cause-width promise. Cause names alone do not establish
whether a refusal occurred before admission or whether an already-admitted
completion failed. General phase attribution and SLO eligibility accounting remain
unimplemented in this diagnostic export; its good/bad/excluded outcomes and denominators are
unchanged. Budget calculation
helpers are available in `src/reliability.zig`; calculated budgets are not
serialized in `reliability.export`. Monotonic latency starts at engine dispatch
entry and includes actor queue waiting and early failures. It excludes daemon
ingress, worker queue waiting, framing and reply flushing, so it is not
end-to-end control latency. Restart resets in-memory history. There is no
independent uptime or scheduled-coverage denominator; absent scheduled coverage,
exact artifact/native provenance and measured baselines prevent an achieved SLO
assertion. UTC-day totals do not establish exact rolling 24-hour burn. Durable
measurement storage and scheduled coverage remain acceptance work. `events.watch` returns the current
snapshot, not a durable event history or streaming alert feed. There is no
implemented incident pager, contractual support channel or daemon repair
endpoint. `repair.start` concerns an account's authorized sources.
It cannot compact/reset durable replay authority, reset request attempts or
clear tombstones to recover local metadata space.

`reliability.lifecycle` has a
separate partial persisted recorder for terminal source removal and native-source
import enrollment. [Enrollment commit preparation](../../src/reliability_commit.zig)
requires the same running job ID and generation to transition to completed or
failed. [Engine integration](../../src/engine.zig) records completed enrollment
only after verified identity and usable grant admission; a failed admitted
terminal transition is a separate outcome. Aggregate changes share the storage
commit with the terminal outcome. Starts, coalesced retries and stale completions
do not create new samples. [Restart/retry coverage](../../src/snapshot_import_tests.zig)
passed within the 219 engine tests in root epoch
`2591137d-2b97-4d1e-ab24-8ba8b43b494a`; see the
[bounded root receipt](../agent-notes/2026-10-05-sess-omux-integrated-delivery.md).
That receipt also records a failed installed synthetic browser-transport
assertion; it is not an installed-browser or whole-product passing claim.

Its native-import timing is explicitly
`admission_to_terminal_before_commit_process_local`: an awake monotonic clock
from admission to the terminal transition before storage commit. It includes
provider work but omits pre-admission queue time and commit/reply latency; local
work and user/provider waits are not split. Restart loses the process-local
start clock; missing duration remains unknown rather than reconstructed.
Persisted counts do not establish scheduled coverage, complete lifecycle
instrumentation, end-to-end user latency or an observed baseline. Capacity and
allocation pressure can leave optional measurement coverage absent while
retaining operation authority. The endpoint reports partial/unmeasured coverage
and `achieved_slo=false`; REL-013 through REL-019 remain broader acceptance work.

Browser ingress follow-on integration passed its durable refusal-ledger fixture
predicates in root epoch `fa904145-6932-41f0-aa68-1672ea3a1b75`:
`//:browser_attempt_transaction_test`, `//:engine_test`, both execution guard
targets and `//:docs_check` passed; exit was zero and descendants were verified
empty. Evidence-manifest SHA256:
`fb1a067cb82d6aa0d9cfd3005e1fd5430d6d934bbc3138907adedb3e13b8d6fe`;
graph SHA256:
`0b739bec638329e21fabd4145795ae03b28b02a167e35ce7c2b94ce3d52b7d63`.
The prior compile failure was corrected; neither it nor the earlier 219-test
receipt proves this new lane. These are fixture predicates, not installed browser,
live enrollment or measured baseline evidence. The bounded
[browser-attempt module](../../src/browser_attempt.zig) specifies immutable
refusal authority for the existing production-disabled `browser.importGrant`
capability refusal only, after envelope, ID, adapter-origin and provenance
validation and confirmation of an existing authorized connected browser source.
Attempt identity is installation/context/source-generation scoped; exact-byte
same-ID retry returns the immutable refusal without another sample. Changed
payload reuse conflicts. Purpose-separated HMACs retain only context and intent
digests, not raw requests or credential capsule bytes.

The specified ledger has 256 records, no eviction/retirement and a 512 KiB
snapshot ceiling. Engine integration commits the fresh terminal refusal and
its `safe_refusal` counter in the same authenticated transaction before reply.
Full ledger, unavailable recorder or admission headroom cannot manufacture a
denominator: the existing truthful refusal remains, with explicit unmeasured
coverage. All timing fields remain unknown. Production browser exports remain
disabled; verified browser enrollment success is not measured by this lane.
Decoder rejections before this stable authority boundary remain missing ingress
coverage and require their own protocol/idempotency prerequisite. Legacy connected
sources without a recorded source generation remain unmeasured until reconnect.
`reliability.lifecycle` exposes `browser_refusal_timing="unknown"`, coverage as
`recorder_unavailable`, `authority_capacity_exhausted` or
`partial_authorized_context_ingress`, and retained/capacity authority metadata
with `retirement_supported=false`. Fixture success does not provide a browser
enrollment baseline or change `achieved_slo=false`.

REL-010: establish each platform/adapter baseline and promotion receipt with
exact commit, artifact, versions, denominator and workload before publishing
achieved SLOs. Preserve synthetic, native conformance and live evidence labels.

REL-011: collect reports containing severity, UTC interval, OS/architecture,
artifact/version/commit, native application version, protocol version, snapshot
revision/capture time, typed error, observed latency, operation state and affected
capability. Snapshot fields currently include `custody_available`, `jobs`,
`observations` and grouped `capacity` with `complete`/`unknown_buckets`; see
[API methods](../../src/control.zig) and
[snapshot projection](../../src/engine.zig). Scrub user labels, source paths,
handles and session identifiers before sharing; no raw account identity, email,
credential, cookie, provider body or PII screenshot belongs in evidence.

REL-012: verify the runbook using declared local platform actions before support
promotion. No-cost health reads inspect local metadata only; do not issue
provider inference, quota-burning admission, enrollment or reconciliation probes
as implicit monitoring. Background authorized account-read polling is distinct
from a health read and can still consume provider rate capacity.
