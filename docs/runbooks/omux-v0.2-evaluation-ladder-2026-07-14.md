# omux v0.2 Evaluation and Dogfood Ladder

Status: active evaluation contract; v0.2 remains unshipped

Date: 2026-07-14

Program: GitHub #463; Linear TIN-2057; Phase 2 Prompt 79

Stable release while this ladder is incomplete: v0.1.15

## 1. Purpose and authority

This runbook defines how an exact v0.2 candidate moves from synthetic,
no-provider-spend evaluation to attended live continuity proof. It is the
operator contract for evidence, dogfood, rollback, and claim promotion. It does
not implement a test harness, authorize provider spend, or promote v0.2 by
itself.

The complete order is indexed by `docs/authority-map.md`. The operative order
for this runbook remains:

1. `AGENTS.md`;
2. Section 0 of `docs/spec/broker-mcp-contract-2026-05-03.md` for the immutable
   same-process, no-prompt success metric;
3. `docs/plans/oauth-mux-v0.2-full-broker-foss-program-2026-07-11.md`;
4. `docs/plans/oauth-mux-v0.2-deletion-ledger-2026-07-11.md`;
5. `docs/security/omux-v0.2-threat-model-2026-07-11.md`;
6. this runbook;
7. `docs/spec/managed-harness-jsonrpc-v2.md`;
8. the shipped Codex adapter contract;
9. the session-authority contract where it does not conflict with the
   authorities above;
10. `CHANGELOG.md` and committed evidence for shipped claims.

Prompt 79 is an execution input, not repository design authority. Its Phase 2
claim boundary is preserved here: deterministic fake-upstream and no-spend
managed-Claude work is readiness evidence only and earns no TIN-2057 golden
credit. Earlier keepalive, restart, prepared-fallback, and v0.1 Codex dogfood
artifacts remain historical shipped evidence; they cannot score this ladder.

## 2. Current truth at the baseline

This runbook was authored from `main` at
`c4622f8e0975273e90bd8663e53eda7ba550f4a2`.

The Phase 2 foundation merged with this exact provenance:

| Field | Baseline value |
| --- | --- |
| Tested candidate commit | `848104c9ab63ba2fba92b89cb94cf48425d32de1` |
| Merged `main` commit | `c4622f8e0975273e90bd8663e53eda7ba550f4a2` |
| Shared source tree | `c0b76e441e95f0e4f1ce621b5cded9d7cb6e79a8` |
| GF Remote Check | run `29302180117`, success on the tested candidate |
| PR CI | run `29302164160`, all nine checks successful |
| Public Source | run `29302164157`, success on the tested candidate |
| Release Proof | run `29303177390`, success on the tested candidate |

That proof covers fail-closed Claude child authority, identity admission, and
refresh classification. It does not cover a listener, managed Claude child,
capability carrier, credential forwarding, provider request, account alternate,
installed v0.2 prerelease, or live continuity.

**TIN-2057 is exactly 0/11. v0.1.15 remains the stable release.** Passing GF,
Public Source, or Release Proof for foundations does not change either fact.

## 3. Vocabulary

- **Candidate**: one source commit and tree projected into one release manifest,
  build ID, target triple, and binary digest. A branch name, working tree, tag
  pointer, or "latest" is not a candidate.
- **No-spend**: the test cannot reach a provider origin, cannot trigger provider
  login or usage polling, and records zero provider calls. Synthetic credentials
  and a deterministic fake upstream are mandatory where request traffic is
  needed.
- **Provider-spend**: any provider-authenticated request, including a usage read,
  revalidation, login, context turn, or handoff attempt. Subscription-backed
  traffic still counts even when no incremental invoice is expected.
- **C1 and C2**: run-local aliases for two distinct, operator-authorized Claude
  provider identities. They are not account labels and must not be stable across
  evidence packets.
- **X1 and X2**: the equivalent run-local aliases for two distinct,
  operator-authorized Codex provider identities.
- **Continuity arrow**: `C1 -> C2` or `X1 -> X2` means one stable harness process,
  one stable native session/context, the exact requested model, an eligible
  first-route failure, exactly one distinct-identity alternate, and success with
  no login, prompt, repair, resume, relaunch, or restart between endpoints. It
  does not mean two harness processes.
- **Golden row**: one of the 11 predicates in Section 7 accepted on TIN-2057 with
  committed, redacted evidence for the exact candidate. Prerequisite evidence is
  not partial credit.

## 4. Proof lanes and claim boundaries

| Lane | Required use | What it proves | What it never proves alone |
| --- | --- | --- | --- |
| Local debugging | Fast iteration on pure, fixture, fake-upstream, documentation, and benchmark code | A developer can reproduce and diagnose a candidate locally | Completion, portability, release readiness, provider behavior, or a golden row |
| GloriousFlywheel | `just test`, `just check`, `just e2e`, or a named benchmark through the remote lane on the exact source commit | Authoritative repository tests and named performance predicates on the GF runner class | Public-source independence, signed installation, or live provider continuity |
| Public Source | The unprivileged GitHub-hosted `Public Source` workflow on the same exact commit | Clean Just/Nix source build without Tinyland/GF credentials or endpoints | GF completion proof, release packaging, or provider behavior |
| Release Proof | The serial GF release-proof target for the exact commit and declared version | Release graph, staging, smoke, handoff, and candidate provenance expected by that target | A signed v0.2 prerelease unless signing artifacts are present, installed dogfood, or continuity |
| Attended live | A foreground operator window after every hard gate below is open | Only the exact provider/model/process/account shape captured by its redacted packet | Another provider, model, platform, mediation level, or unattended/default-managed behavior |

GF, Public Source, and Release Proof are complementary. None substitutes for
another. A local run may be attached as diagnostic context, but it must be
labeled `local_debug_only` and is never the cited acceptance result.

## 5. Hard gates

Every gate is closed by default. Tracker status, operator authorization, and
proof links must be re-read immediately before the affected stage.

| Gate | Opens when | Blocks while closed |
| --- | --- | --- |
| `O-OWNERSHIP` | The attending operator confirms the exact candidate, exact model, authorized ownership or use of every participating identity, test window, and rollback target | Enrollment, identity use, installation, service mutation, and live dogfood |
| `S-PROVIDER-SPEND` | The operator gives contemporaneous approval for one named stage with finite request, token, elapsed-time, and, where billable, currency limits | Every provider-authenticated call. Standing approval and unattended loops are invalid |
| `R-TIN-1759` | TIN-1759's launchd secret-containment gate is Done and its accepted proof is linked from the stage record | Resident-service install, enable, disable, restart/kickstart, and all installed-binary dogfood |
| `L-TIN-2077` | TIN-2400 exact-model readiness and TIN-2040 shared-lease/performance prerequisites are accepted, Stage 5 shadow/manual-route proof is accepted, and TIN-2077 explicitly opens an attended automatic-alternate window | Production automatic alternates and live `C1 -> C2` or `X1 -> X2` acceptance |
| `P-PROMOTION` | A human reviews the committed redacted packet, confirms all 11 rows on one candidate, and explicitly updates TIN-2057 and release authority | Stable aliases, default-managed behavior, public continuity claims, and replacement of v0.1.15 |

An agent may prepare commands or a dry-run packet, but it must not infer any of
these approvals. Provider login and re-enrollment are operator actions. A
confirmation artifact showing a gate is closed proves only that no gated action
ran.

## 6. Exact candidate provenance

Before Stage 2, create one sanitized candidate record. Before Stage 4, complete
all release fields. Every later packet must repeat, not merely link to, these
values:

- 40-character source commit and source tree IDs;
- tested PR-head commit, merged commit, and explicit tree-equality result when a
  squash or rebase changes the commit ID;
- declared version, release profile, build ID, target triple, and adapter
  protocol versions;
- release-manifest digest and exact binary SHA-256;
- signature-bundle digest and verification result, SBOM digest, and provenance
  digest;
- GF, Public Source, and Release Proof run IDs, each run's exact head SHA,
  conclusion, and target name;
- installed binary version, build ID, and digest observed on the dogfood host;
- UTC start and finish timestamps and the stage identifier;
- repo-managed recipe name, its source blob ID, and a sanitized argument schema.
  This is the binding meaning of Prompt 79's "exact commands" requirement; do
  not preserve a raw shell command, path-bearing invocation, or environment
  dump.

The installed digest must equal the signed artifact selected by the manifest.
The Claude and Codex live arrows must use the same source commit, tree, release
manifest, and binary digest. If any product, test, release, or evidence-redaction
code changes, the candidate changes and all affected stages must rerun. A green
run on an ancestor, a different PR head, or a tree-unequal merge is stale.

## 7. TIN-2057 golden scorecard

Score a row only when every conjunct passes and TIN-2057 links the committed
packet. Stages 0-3 are prerequisites and cannot move the score. A synthetic
alternate is never live continuity credit.

| Row | Predicate | Required proof |
| --- | --- | --- |
| G1 `claude_continuity` | One managed Claude process preserves model and context through provider-originated quota exhaustion and exactly one `C1 -> C2` alternate | Stage 6 attended live packet |
| G2 `replay_memory_safety` | Ambiguous send, partial write, cancellation, started response, 5xx, oversize, and exhausted memory budgets never cross identities; request, sidecar, and host limits degrade to stream-once; no request bytes reach disk | Final-candidate GF negatives plus Stage 4 acceptance packet |
| G3 `exact_model_readiness_and_leases` | Exact model preservation, advisory usage freshness/kill-switch/reactive fallback, sticky least-loaded selection, stale-owner cleanup, and deterministic lease behavior hold under concurrency | Final-candidate GF readiness/concurrency packet, Stage 4 resident-snapshot check, and both live arrows |
| G4 `performance` | Every metric in Section 8.7 passes on the final candidate with no local fallback | Dedicated GF benchmark packet |
| G5 `managed_boundary_and_redaction` | Capability carrier, loopback bind, fixed origin, auth stripping, redirect/SSRF refusal, bad-token zero-call behavior, graceful and abrupt sidecar teardown, and the Section 8.5 redaction predicate pass | Final-candidate GF security/death packet plus redaction reports for all later stages |
| G6 `resident_independence` | Resident absence and an allowed restart cannot make it the session proxy, expose request bodies, or corrupt a managed session | Stage 4 after `R-TIN-1759` |
| G7 `distribution_and_rollback` | Signed macOS install/upgrade, Linux beta install/upgrade, clear Windows unsupported failure, exact installed provenance, and Section 8.6 rollback all pass | Stage 4 installed-candidate packet |
| G8 `codex_continuity` | One managed Codex process preserves model and context through provider-originated quota exhaustion and exactly one `X1 -> X2` alternate | Stage 7 attended live packet |
| G9 `opencode_conformance` | OpenCode exercises the same surface-v2 lifecycle, route/lease vocabulary, redaction, bounded failure, unknown-field compatibility, and explicit unsupported-capability behavior without weakening Claude | Final-candidate TIN-1798 conformance packet |
| G10 `bounded_failure` | All identities exhausted and resident unavailable terminate with one bounded typed outcome, trusted `Retry-After` where available, no loop, no invented capacity, and no harness restart | Final-candidate GF packet plus Stage 4 installed check |
| G11 `beta_cohort` | Three clean non-maintainer users, including one Linux user, complete install, enrollment, managed launch, handoff, repair, and rollback on the exact candidate | Stage 7 cohort packet |

Rows remain independent. For example, G5 cannot borrow redaction from a schema
fixture, G7 cannot borrow a source build from Public Source, and G1 cannot borrow
the shipped v0.1 Codex evidence.

## 8. Cross-cutting acceptance predicates

### 8.1 Identity

Before either live arrow, a local preflight must prove in memory that route 1
and route 2 represent distinct provider identities and are authorized for the
operator. Distinct route or account handles are not sufficient. Persist only
`distinct_provider_identity: true` and run-local aliases `C1`/`C2` or `X1`/`X2`.
Do not persist identity hashes, labels, account IDs, emails, organizations, or
user names.

### 8.2 Exact model

For every request in an accepted arrow:

1. capture the top-level requested model before election;
2. require the first and alternate upstream attempts to carry the byte-identical
   model identifier;
3. require the harness-visible successful result to report the same public model
   identifier through a trusted local observation;
4. reject family inference, aliases, downgrade, substitution, and an
   account-wide availability claim used as model parity.

The packet may contain the public model identifier and equality booleans. Any
mismatch fails the run immediately; a successful response from a different
model is not continuity.

### 8.3 Process

After launch stabilization, the adapter must designate one harness authority
process. Wrapper or shim processes that exit before this point are not the
authority process. Locally derive a process fingerprint from PID, process birth
time, executable file identity, and managed-session parentage, then persist only
a run-local opaque fingerprint.

An arrow passes only when:

- the fingerprint before the route-1 context turn, at the eligible failure, and
  after route-2 success is identical;
- `harness_spawn_count == 1`, `harness_restart_count == 0`, and
  `harness_exec_replacement_count == 0`;
- the broker session and sidecar remain the same session, with no sidecar
  replacement hidden as recovery;
- no operator or agent runs login, resume, repair, relaunch, signal-based
  restart, or manual account switch during the interval.

Raw PIDs, process arguments, executable paths, working directories, and
environment values must not enter evidence.

### 8.4 Context and retry

The context probe uses a fresh, non-sensitive, high-entropy marker held only in
memory. A successful route-1 turn establishes it. The handoff-triggering request
depends on that earlier context; the route-2 result is compared in memory and
only `context_match: true|false` is persisted. The native session's run-local
opaque handle must also remain equal. Prompt text, response text, marker bytes,
session IDs, and body hashes are forbidden in evidence.

The handoff-triggering request passes only when all of these are true:

- route 1 returns a provider-originated, explicitly classified pre-body 429
  `quota_exhausted` result for the stable product metric;
- the broker assigns one opaque request handle and records exactly two upstream
  attempts total for it;
- attempt 2 uses one distinct provider identity, preserves the exact model, and
  succeeds before the request deadline;
- `same_route_retry_count == 0`, `alternate_count == 1`,
  `third_attempt_count == 0`, and the route-1 failure is not delivered as the
  successful harness result;
- no wait occurs more than once or for more than 30 seconds, and any wait fits
  the original request deadline.

Synthetic GF coverage must additionally prove that explicit pre-body 401 and
403 can consume the same single alternate slot, while 5xx, transport ambiguity,
partial send, cancellation, a started response, and replay-budget overflow
cannot. A request can consume one safe same-route transport retry or one
cross-identity alternate, never both. A same-route retry requires proof that no
request byte was sent; ambiguous or partial send state returns the original
failure without replay.

A replayable body must remain wholly in memory within 32 MiB per request,
64 MiB per sidecar, and 256 MiB per host. Reservation failure, a known oversize
body, or a chunked/unknown body crossing 32 MiB irrevocably changes the request
to stream-once. Cancellation, overflow, and teardown release reservations. A
memory-only random sentinel scan must report zero request bytes persisted to
disk; the sentinel itself must not enter evidence.

### 8.5 Redaction

Evidence is allowlist-only. It may contain booleans, bounded counts, durations,
public model identifiers, typed status enums, run-local opaque handles, UTC
timestamps, public source/artifact digests, and public workflow IDs.

It must not contain:

- access, refresh, identity, API, session-capability, or cookie material;
- authorization headers, child environments, provider payloads, crash dumps, or
  raw protocol transcripts;
- raw or stable-hashed account, user, email, organization, session, or machine
  identities;
- absolute, home-relative, config, credential, session, binary, working, or
  evidence filesystem paths;
- prompts, tool inputs, request bodies, response bodies, assistant output,
  context markers, or screenshots containing any of them;
- command lines or environment dumps that could reconstruct a path, identity,
  endpoint override, or credential source.

Do not hash low-entropy forbidden values as a substitute for redaction. Each
packet needs an automated secret/PII/path/content scan and a human review. Store
only the scanner version, policy digest, counts, and pass/fail result. A finding
invalidates the packet; remove the raw artifact before commit and rotate any
exposed credential.

### 8.6 Rollback

Rollback restores product binaries and service state, never old credential
material. Before Stage 4, verify that the signed v0.1.15 stable artifact remains
available and record its public digest. The candidate must install without
overwriting stable aliases before promotion.

A rollback passes only when:

- no managed harness process is active when binary or service state changes;
- the candidate sidecar is gone and its capability, leases, and replay
  reservations are released;
- the prerelease is disabled or removed and command resolution again selects the
  expected signed v0.1.15 version and digest;
- resident-service enabled/disabled state equals its pre-stage state;
- canonical harness config, enrolled credential stores, and session history are
  reported unchanged by a local typed comparator without persisting paths or
  content digests;
- rotating-token lineage is left at its newest valid state. A forensic or stale
  token backup is never restored; hard lineage failure requires provider-owned
  re-enrollment.

Rollback failure closes `O-OWNERSHIP` and blocks further dogfood on that host.

### 8.7 Performance

Performance is no-spend and uses the deterministic fake upstream on a pinned GF
runner class with local fallback disabled. The packet records runner class,
clock source, workload ID, sample counts, and aggregate metrics, not request
bodies.

- **Routing/auth overhead**: after at least 1,000 warmups, measure at least
  10,000 requests from authenticated sidecar ingress through readiness to begin
  upstream I/O. Require p95 <= 5 ms and p99 <= 10 ms.
- **Streaming throughput**: alternate direct and brokered trials on identical
  in-memory payload fixtures for at least five 30-second trials per path.
  Require the median broker bytes per second to be at least 95% of the median
  direct bytes per second.
- **Idle RSS**: after 60 seconds without requests, sample the sidecar five times
  one second apart. Require the maximum resident set size to be <= 20 MiB.
- **Lock and lease load**: run 20 concurrent managed sessions against 50 eligible
  synthetic identities for at least 100 election/state cycles per session.
  Require zero lock timeouts, zero missed session completions, no stale owner
  counted after cleanup, every session to complete all cycles before its
  deadline, and a maximum-minus-minimum active-lease load <= 1 at synchronized
  steady-state checkpoints.

Any debug instrumentation that materially changes timing invalidates the metric.
A local benchmark may diagnose variance but cannot satisfy G4.

### 8.8 Advisory usage and refresh

The default-on Claude usage reader must remain advisory and resident-owned.
Final-candidate GF tests must prove all of these predicates with deterministic
fixtures and provider networking disabled:

- one coalesced in-flight read per account, a five-minute normalized freshness
  window, a five-minute negative cache for a valid empty result, and no raw
  response persistence;
- tolerant unknown-field parsing but required scope, window, bounded usage or
  remaining value, absolute reset, and exact model for model-scoped rows;
- invalid-row exclusion, one redacted event per schema fingerprint, and a
  per-account process-lifetime kill switch for missing top-level structure or
  an unsupported schema/version;
- stale, missing, contradictory, killed, or resident-unavailable advisory state
  falls back to reactive request-path evidence without stopping the harness or
  inventing route/model readiness;
- observed exhaustion remains trusted through reset, availability expires at
  its deadline, and direct request-path evidence outranks advisory state.

The sidecar may refresh only the elected account inside the request-boundary
lead window. Integration tests must run resident and sidecar refresh attempts
through the same per-account flock and prove bounded acquisition, no deadlock or
starvation, and one writer. Transient lock, transport, endpoint, or store failure
remains unproven and cannot quarantine a lineage. Only hard provider evidence of
an expired, reused, revoked, or otherwise invalid refresh-token lineage may
quarantine it. No stale or forensic backup may be restored automatically.

Stage 4 repeats the resident-snapshot ownership, reactive fallback, and
shared-flock predicates with the installed candidate and provider egress denied.

## 9. Stages 0-7

Stages are sequential. `blocked` is a valid result; silently skipping a gate is
not. A later stage cannot repair missing evidence from an earlier stage.

### Stage 0: authority and candidate lock

Scope: static, synthetic, no spend.

1. Re-read the authority chain and current tracker states.
2. Freeze the source commit/tree and create the initial sanitized candidate
   record.
3. Record all hard gates as closed unless current evidence opens them.
4. Map every planned assertion to one golden row and one owning test or packet.

Exit: the candidate and claim boundary are unambiguous. No runtime, service,
credential, installed binary, provider, or golden claim exists.

### Stage 1: local synthetic debugging

Scope: pure reducers, generated contract instances, property tests, fake
identities, and deterministic fixtures. Provider networking and provider login
must be impossible.

Exercise exact-model admission, refresh classification, capability comparison,
attempt accounting, memory reservation transitions, lease cleanup, bounded wait,
teardown, and redaction. Local commands are developer feedback only.

Exit: local diagnostics are clean enough to dispatch remote proof. Label every
result `local_debug_only`; TIN-2057 remains unchanged.

### Stage 2: authoritative fake-upstream conformance

Scope: GF remote tests against a deterministic fake upstream, synthetic
credentials only, zero provider calls.

Exercise capability carrier and zero-call rejection; fixed-origin and redirect
negatives; byte-preserving streaming and cancellation; 401/403/429 alternate
shapes; 5xx pass-through; ambiguous/started/oversize no-replay paths; all memory
budgets; exact model; route identity admission; graceful teardown; abrupt
sidecar death with capability, lease, and reservation reclamation; resident
absence; bounded all-exhausted behavior; and every Section 8.8 advisory-usage
and refresh predicate. Counters must reconcile every accepted and rejected
request.

Exit: the no-spend sidecar contract is remotely reproducible. This is Prompt 79
readiness evidence and earns zero golden rows.

### Stage 3: exact-candidate no-spend qualification

Scope: one candidate, no provider calls.

Require all of the following on the same source commit:

1. GF Remote Check and the dedicated Section 8.7 GF benchmark;
2. Public Source without private credentials or endpoints;
3. serial Release Proof for the declared candidate version;
4. a disposable real-Claude carrier launch against a no-spend test boundary,
   proving one real Claude process receives the managed capability while the
   frozen authority map preserves operator HOME, working directory, project and
   session history, and normal settings; uses a neutral per-session
   `CLAUDE_CONFIG_DIR`; refuses canonical or enrolled-store overlap; scrubs
   inherited provider/auth/base-URL aliases; cannot read or write enrolled
   credentials; and leaves canonical state unchanged;
5. Codex and Claude surface-v2 lifecycle round trips as owned by TIN-1798,
   including unknown-field compatibility and explicit unsupported-capability
   behavior; OpenCode conformance remains independently tracked as G9 and is not
   inferred from either reference adapter;
6. a complete redaction report and candidate provenance reconciliation.

Exit: the source candidate is eligible to become a signed prerelease. These
proof classes stay distinct and still earn no Prompt 79/TIN-2057 golden credit.

### Stage 4: installed candidate, resident, and rollback rehearsal

Scope: signed prerelease on clean macOS and Linux test hosts, provider egress
denied, no provider calls.

Entry requires `O-OWNERSHIP` and `R-TIN-1759`. While TIN-1759 is open, this
entire stage is blocked; do not install the candidate, mutate launchd/service
state, or reinterpret a repo-local run as installed dogfood.

Verify exact installed provenance, clean install and upgrade, explicit Windows
unsupported behavior, resident absence and one controlled restart, installed
resident-snapshot ownership and reactive fallback, shared-flock serialization,
abrupt sidecar-death reclamation, bounded all-exhausted behavior, teardown, and
Section 8.6 rollback to v0.1.15. Provider egress counters must remain zero.
Reinstall the candidate only if the later live window is separately authorized.

Exit: installed and rollback behavior is accepted for the exact candidate.
Eligible non-live golden rows may move only after TIN-2057 links the committed
packet; G1, G8, and G11 remain open.

### Stage 5: attended real-origin shadow and manual route

Scope: one installed managed Claude process, then two authorized Claude
identities, with production automatic alternates disabled.

Entry requires Stages 0-4, `O-OWNERSHIP`, `S-PROVIDER-SPEND`, and
`R-TIN-1759`. TIN-2077 must record the named attended shadow/manual window, but
`L-TIN-2077` remains closed. Record finite spend ceilings before any provider
call and keep background polling disabled except the resident behavior being
explicitly observed.

First run shadow observation on one selected identity: preserve the exact model,
compare broker decisions with the direct request-path outcome, and prove that
advisory absence or disagreement cannot change the response or authorize an
alternate. Then run a separate operator-selected manual-route proof in the same
managed process with C1 and distinct C2. The operator may select C2 only at a
safe request boundary; the broker must not select it automatically. Prove both
identities admit the exact model, request-path evidence outranks advisory state,
and no login, canonical mutation, restart, or unsafe replay occurs.

Exit: committed redacted shadow and manual-route packets are accepted on
TIN-2077. This stage earns no golden row and does not authorize production
automatic alternates. It is a prerequisite for opening `L-TIN-2077`.

### Stage 6: attended automatic Claude `C1 -> C2`

Scope: one stable managed Claude process and two authorized Claude identities.

Entry requires Stages 0-5, `O-OWNERSHIP`, `S-PROVIDER-SPEND`,
`R-TIN-1759`, and `L-TIN-2077`. Record finite spend ceilings before any
provider call. Disable background loops and unrelated provider polling. If C1
does not reach the required provider-originated quota state within the approved
budget, stop as `blocked_no_eligible_observation`; do not manufacture failure or
increase the budget silently.

The accepted sequence is:

1. launch one installed managed Claude process on the exact candidate;
2. complete one context-seeding success on C1;
3. keep the same process, native session, context, and exact model;
4. observe C1's provider-originated pre-body `quota_exhausted` 429 on the
   handoff request;
5. make exactly one automatic alternate to distinct identity C2;
6. complete that request successfully on C2 and pass the in-memory context
   comparison;
7. tear down cleanly without login, prompt, repair, resume, relaunch, manual
   switch, or restart.

Exit: G1 may move only after redaction review and committed exact-candidate
evidence. Failure follows Section 10 and does not weaken the retry predicate.

### Stage 7: attended live Codex `X1 -> X2` and beta closeout

Scope: one stable managed Codex process, two authorized Codex identities, then
the clean-user cohort on the same exact candidate.

Repeat every Stage 6 gate and predicate for `X1 -> X2`; shipped v0.1 Codex
evidence is regression context only. The accepted Codex run needs a new
provider-originated quota event, one distinct-identity alternate, exact model,
stable process and context, and no manual mediation.

After G8 is accepted, three non-maintainer users, including at least one Linux
user, independently complete clean install, enrollment, managed launch,
handoff, repair, and rollback. Their packet uses run-local tester aliases and
platform names only. A maintainer replay on the user's host does not count as a
clean-user completion. Each user opens fresh `O-OWNERSHIP` and
`S-PROVIDER-SPEND` gates; approval from another user or the canonical Codex run
does not transfer.

Exit: complete G9 if it is still open, then review all 11 rows against one
candidate. A score below 11/11 leaves v0.2
experimental and v0.1.15 stable. At 11/11, `P-PROMOTION` still requires an
explicit human release decision; promotion is never automatic.

## 10. Stop, cleanup, and rollback rules

Stop the active stage immediately on any of these conditions:

- candidate provenance mismatch, dirty or untracked executable, stale remote
  run, or installed digest mismatch;
- closed or unverifiable operator, spend, restart, prerequisite, or live gate;
- unexpected provider call during Stages 0-4;
- identity ambiguity, model mismatch, process/context fingerprint change, login
  prompt, or manual intervention;
- more than two upstream attempts, both retry forms on one request, replay after
  an excluded outcome, or a third route;
- provider-spend ceiling or deadline reached;
- secret, identity, path, prompt, response, or body material entering an
  artifact;
- incomplete teardown, rollback failure, or resident service assuming request
  proxy ownership.

On stop: block new requests, terminate the managed session through typed
teardown, release capabilities/leases/reservations, and perform Section 8.6
rollback when installation or service state changed. Preserve only a sanitized
failure summary. Do not keep a raw transcript for diagnosis, do not restore a
stale refresh token, and do not call the result partial continuity.

## 11. Evidence packet contract

An accepted packet is committed under the repository's immutable evidence
surface only after redaction passes. Use a dated directory, but do not emit its
local filesystem path into packet content. At minimum it contains sanitized
records for:

- candidate provenance;
- gate states and operator authorization timestamps;
- typed stage result and exact golden rows claimed or explicitly left open;
- aggregate fake/provider call and attempt counters;
- model/process/context/retry predicate booleans;
- aggregate performance metrics where applicable;
- teardown and rollback predicate booleans;
- automated and human redaction reports;
- exact GF, Public Source, Release Proof, and attended-run references;
- a claim-boundary statement naming what the packet does not prove.

Do not commit terminal recordings, screenshots, raw logs, HTTP captures, process
snapshots, command environments, provider dashboards, prompts, or responses.
Collectors must reduce sensitive observations to the allowlisted typed fields in
Section 8.5 before persistence.

Evidence is immutable after acceptance. A later candidate gets a new packet and
cannot edit an older packet into broader proof.

## 12. Promotion rule

Until TIN-2057 is 11/11 on one exact candidate, all v0.2 artifacts and docs must
say `future`, `experimental`, or `unshipped`. A prerelease must not replace
stable aliases, and no result in this ladder authorizes default-managed mode,
unattended provider spend, or continuity claims for an unmanaged harness.

The stable-release change happens only after the full scorecard, explicit
operator review, release-authority approval, and a final exact-candidate
Release Proof. Otherwise v0.1.15 remains the honest stable release.
