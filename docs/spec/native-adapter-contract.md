# Native adapter contract

Status: active reset contract, experimental and unshipped, 2026-10-02.
The [native account-lifecycle reset](../plans/omux-native-account-lifecycle-reset-2026-10-02.md)
owns architecture; [implementation evidence](../implementation/native-reset-evidence-2026-10-02.md)
owns completed proof. This document defines acceptance requirements and records
current implementation boundaries. Requirements do not create wire methods or
promote capabilities. Historical release claims remain unchanged.

Install Omux, authorize sources once, and launch applications ordinarily. A
supported integration substitutes compatible authorization in the same native
application process, preserving native sessions, history, tools and approvals,
without routine handoff prompts. Wrappers, alternate homes, supervised relaunch,
prepared fallback and synthetic routing are insufficient. Omux owns each
application's authentication integration contract and implementation; no
OpenAI-provided Omux hook is assumed. Delivery is qualified per application as
plugin, configuration, upstream contribution or explicitly maintained application
modification. Upstream acceptance is a prerequisite for upstream delivery only.
Version-bound live proof remains required for supported continuity through every
delivery option. Current Codex candidates are experimental evaluation artifacts;
unmodified Codex continuity remains unsupported by current evidence.

## Authority and implemented interfaces

The daemon owns account lifecycle, encrypted custody, policy and route decisions.
Adapters own native protocol boundaries and acceptance evidence. Native session
stores remain authoritative in place. An identity, account, source, grant,
resource, observation, binding and lease are separate entities. Authentication
factors are enrollment requirements; an authorized browser reader is not an API
grant. A label or copied native account hint cannot establish identity.

The current local control protocol is version 2, defined by
[control.zig](../../src/control.zig), with handlers in
[engine.zig](../../src/engine.zig). It uses JSON-RPC 2.0 envelopes on private
local channels with bounded framing and peer-user checks. This is a fresh local
API, not the deleted managed-harness JSON-RPC contract. General control replies
contain redacted metadata and opaque handles, never credential payloads.
Account snapshots expose the stored `identity.verified` boolean alongside
`identity.provider`; issuer, subject and tenant remain private. Consumers must
require boolean `true` before treating an account as verified. Installed runtime
support for this field requires qualification of the exact delivered bytes.

| Surface | Implemented methods and limits |
| --- | --- |
| Public integration control | `integrations.status`, `integrations.discover`, `integrations.install`, `integrations.remove`, `integrations.attach`, `integrations.detach`; bounded selected-context discovery is read-only. Qualified selection carries the exact owner tuple; attachment requires a compatible hook and a freshly verified reachable endpoint. |
| Trusted adapter channel | `credential.import`, `adapter.owner.register`, `adapter.acquire`, `adapter.materialize`, `adapter.report`, `adapter.metadata`, `adapter.releaseBinding`, `adapter.gitGet`, `adapter.gitErase`; owner registration requires fresh socket-derived process proof |
| Public lifecycle and usage | `account.pause`, `account.resume`, `account.drain`, `account.forget`, source operations, `usage.summary`, `system.health`, `reliability.export` and `operation.status`; upstream revoke is not an implemented method |
| Shared setup control | `setup.readiness`, `setup.plan`, `setup.evidence`, `setup.refresh` are implemented in source. Refresh starts one bounded background installation probe using immutable launch selectors; evidence reports cached observations and freshness. Plans do not rewrite managed files. Source presence does not prove installed readiness or successful filesystem collection. |
| Current Codex owner V2 endpoint | `owner/capabilities`, `owner/threads`, `owner/identify`, `owner/register`, `owner/unregister`, `owner/announce`; private authenticated Unix packet transport with an explicit endpoint, bounded at 64 KiB |
| Separate candidate read-only status extension | `owner/attachment/status` has two passing local Rust predicates in epoch `cd8c87d7-85f4-4c41-836c-18d8a6f7585c`; installed discovery and ordinary TUI/resume remain unproved. It must expose exact committed attachment attribution, never infer retirement from absence. The preserved164-change/installed4b pair does not supply this method's proof. |
| Preserved Codex protocol-1 candidate extension | `omux/broker/capabilities`, `omux/broker/register`, `omux/broker/unregister`, `omux/broker/thread/status`; belongs to the preserved upstream patch candidate, absent from stock Codex; legacy WebSocket inspection confers no current owner custody |
| Intent requiring later implementation | Explicit refresh adoption/renewal ownership transfer, upstream revocation and a general adapter observation publication interface; no method names or executable guarantee are declared here |

Method catalogs describe source behavior; they are not complete generated
per-method parameter schemas. The historical broker/MCP spec supplies the
same-process product bar only where compatible with the reset, not current wire
authority. [catalog.zig](../../src/catalog.zig) distinguishes declared,
implemented, synthetic-proven and live-proven capabilities. Its `normal_launch`
flag describes intended entrypoints, not a passed ordinary-launch gate.

Resident validation is declared in [delivery/BUILD.bazel](../../delivery/BUILD.bazel):
`//delivery:resident_namespace_qualification` checks the provider-free namespace,
and `//delivery:resident_codex_live_continuity` evaluates ordinary TUI preparation,
cold native resume and two completed turns in the same resumed process after an
explicit account-A drain. The [controller](../../delivery/resident_codex_live_controller.py)
and [guardian](../../tools/guard_resident_continuity_profile.py) require verified
resident accounts and independently qualified native and daemon artifacts.
Declared targets and their source models do not establish installed or live proof.

Control mutations require a stable opaque `operation_id` and nonnegative
`expected_revision`. JSON-RPC `id` remains response correlation only. Query
`operation.status` after response loss; mismatched reuse, stale revisions and
indeterminate operations fail closed. Poisoned custody refuses outcome queries
rather than reporting an uncommitted cache. Cancellation uses `target_operation_id`
separately from its own mutation ID. The native adapter capability protocol and browser native messaging remain
version 1; neither inherits control version 2.

## Native credential-source context acceptance gap

Daemon-default enrollment and verified active-application source context are
separate. Omitted Codex `source_path` in [engine.zig](../../src/engine.zig)
resolves from the daemon's `HOME`/`CODEX_HOME`; it does not identify the context
used by an independently ordinary-started application. Selected-context discovery
in [native_probe.zig](../../src/integrations/native_probe.zig) authenticates
owner/thread incarnations but carries no credential-source context authority.
Native conversational context reconstruction and session/history preservation
are not credential-source discovery. This bridge is unimplemented and requires
version-bound native/daemon qualification; no method or capability is introduced
by this contract. The product requires discovery without asking users for raw
profile locations, and ordinary launch without an Omux wrapper or alternate home.

Acceptance requires:

- The compatible native owner declares its actual resolved source context through
  the existing authenticated owner boundary. Opaque source-context authority is
  bound to owner, process nonce, peer witness and endpoint generation, plus thread
  incarnation when applicable. Hints, guessed home/profile paths or arbitrary
  process/environment scanning cannot establish this authority.
- Explicit source acquisition consent precedes credential access. Controls pass
  opaque authenticated context authority, never raw paths, credentials or identity
  PII. Trusted daemon acquisition validates bounded owned native-store custody and
  rechecks original owner/context identity before and after; stale, replaced,
  ambiguous or unsupported contexts refuse.
- The [source lifecycle contract](native-lifecycle-and-custody.md) still requires
  provider identity verification before activation, same-identity deduplication,
  ambiguity quarantine and forget tombstones. Native import keeps renewal
  ownership external; source consent, verified identity, refresh adoption and
  native attachment remain separate. Accepted requests/tools and history are not
  replayed.
- Exact source-bound tests cover different ordinary-native/daemon homes, missing
  consent/custody, forged context/path, stale owner/thread/generation, replacement,
  ambiguity and lost replies without repeated mutations. Actual ordinary launch,
  authenticated source selection, verification and retained normal custody need
  separate evidence before attachment or same-process handoff claims.

Existing daemon-default and explicitly selected sources retain their narrower
meaning. Missing native declarations report the gap; stock Codex and experimental
candidates gain no support from these requirements. Existing TIN-5338 native and
TIN-2063 account-lifecycle carriers retain implementation/evidence ownership;
no new ticket or completed acceptance is implied.

## Common lifecycle and safety requirements

Explicit setup verification has scoped historical Linux passes: `33452a55`
engine/Qt transport/setup UI and `08581f31` CLI/Qt transport/setup UI/verification/
collector; the latter overall batch failed. Experimental Linux epoch
`ef255a3e-8d6d-4bb7-a044-d9a42e20aded` passed all twelve targets with zero
controller/workload exits and empty descendants, including live self-image/
collector checks, engine timeout classification, stalled-service bridge, CLI 16,
Qt installed custody/third-restart sealed replay and paired core/browser
registration. The [installed setup tuple](../tracker-updates/integrated-delivery-installed-setup-2026-10-05.json)
binds these setup/channel predicates to exact experimental Linux artifacts.
Darwin/Swift remain unrun. Actual pinned Chromium/private-profile synthetic
service recovery passed in `c8f63b83-f9cb-4233-a01c-5d1e6f30f33d`, exit zero and
empty descendants, with `OMUX_INSTALLED_CHROMIUM_SYNTHETIC_SERVICE_RECOVERY_OK`.
The [exact tuple](../tracker-updates/integrated-delivery-chromium-2026-10-05.json)
covers health, no-permission/tab boundaries, synthetic pending metadata,
original-ID recovery across browser restart, distinct disconnect and preserved
independent sources. Toolbar consent, granted permission, provider acquisition
and native continuity remain false. Exact-generation daemon restart passed in
`fb13c1ae`, bound by the [restart tuple](../tracker-updates/integrated-delivery-restart-2026-10-05.json).
Committed lost-reply recovery and manual Chromium reload/reconnect joined to that
generation remain unproved; full browser
acceptance stays open.
End-to-end reliability/coverage and achieved SLOs remain unproved. See the
[resume ledger](../tracker-updates/integrated-delivery-resume-2026-10-05.json)
and [session record](../agent-notes/2026-10-05-sess-omux-integrated-delivery.md).
Scoped passing targets do not close other failed product gates.
`omux setup verify` invokes
identified `setup.refresh` with exactly `operation_id` and `expected_revision`;
empty refresh remains diagnostic and unmeasured. Existing external mutation
authority is the sole durable record, with started state and prepaid terminal
space committed before worker execution. Exact replay returns immutable cached
results, conflicting reuse fails, and busy/missing installation selection produces
a safe refusal. Collection timeout produces immutable `safe_refusal` with
`collection_timed_out`, null duration and seven unknown phases; its dedicated
refusal count never contributes verification completion. Shutdown/restart uncertainty never permits automatic reissue;
query `operation.status` with the same ID.

Schema-v1 terminal facts have seven fixed phase reason/outcome pairs in order:
artifact, service, vault, source, identity, grant, native. `verification_completed`
means the local check completed, not installation/enrollment/handoff success.
`reliability.lifecycle.setup_verification` derives bounded facts from existing
4096-entry mutation authority without a new ledger, persisted field or migration.
Started/indeterminate, old-window, future-clock and missing timing remain visible.
Timing is `admission_to_terminal_before_commit_process_local`, not end-to-end
latency or measured coverage. This source adds no achieved-SLO or support claim.
Collector backing-file mapping identity is diagnostic evidence, not executable
memory attestation or native application identity proof.
Joint-readiness target passed 248 cases (six new/242 imported) in `c5d684a2`,
including owned-environment missing-receipt collection/replay/SQLite restart.
Setup verification/docs/source capture passed too, but the fourteen-target batch
failed overall with exit 3/empty descendants on two Yoga launch-fixture lifecycle
errors. The summary derives exclusive action-required,
unknown or all-ready counts from retained completed verification facts, with
action-required taking precedence and overlapping `unknown_phase_present` kept.
Refused/unresolved/out-of-window facts and replay add no joint sample. Six passing new
predicates include actual owned-environment collection/replay/SQLite restart;
all-ready remains zero for that collection because native readiness has no
producer. Pure all-ready is fixture-only. Complete user-demand denominator and
installation-success measurement remain false; no setup/SLO/gate promotion follows.
Current experimental AUTHORITY/CONTAINMENT/CHANNEL/SETUP/DELIVERY predicates pass.
Local SPA import/render/archive passed in `b62`; its
[exact tuple](../tracker-updates/integrated-delivery-spa-2026-10-05.json) remains
unsigned/unpublished. Foundation `9fc` failed overall while browser-root,
acquired-source, setup and selected-stage predicates passed. Corrected selector
`d4fb` passed 27 predicates in the
[selector receipt](../tracker-updates/integrated-delivery-selector-2026-10-05.json).
These facts do not promote browser enrollment, native continuity or reliability.
Native dependency producer `0ebaff4d` passed its first 16 actual SDK objects with
exit zero and empty descendants. The [dependency tuple](../tracker-updates/integrated-delivery-native-dependencies-2026-10-05.json)
retains its dated first-16 scope. The [later verified native union](../tracker-updates/integrated-delivery-native-union-2026-10-05.json)
has 305 unique verified objects, 1,410 missing and 42 unresolved dependencies.
This proves acquisition only, not compilation closure, launch/resume or continuity.
Rerun `bd412392` was rejected with controller/workload 125 and unproved cleanup;
apparent passes are unadmitted and promote no prior receipt or gate.

Acceptance IDs below are stable references. Keep their meaning when adding
evidence; a changed predicate needs a new ID. A requirement may be implemented
locally without passing native or live conformance.

| ID | Required behavior and acceptance predicate |
| --- | --- |
| `NAC-001` Native entrypoint | Ordinary launch and native resume use the integration after reversible setup, with unchanged native home/session authority and no wrapper requirement. Record actual application version/build and process provenance. |
| `NAC-002` Capability negotiation | Verify protocol version, application version, endpoint ownership and required hook capabilities before activation. Missing, malformed, unknown or incompatible support fails closed with an explicit missing capability. Stock account RPCs do not establish per-request authority. |
| `NAC-003` Existing attachment | Attach only through a verified native hook to a loaded native session/thread. Native authorization workers must drain or retain their ownership fence. An unreachable endpoint, active request or uninspectable context cannot be silently converted to an attached binding. |
| `NAC-004` Binding isolation | Namespace bindings by application, session and external binding ID. Snapshot binding and route authority per request. Concurrent threads/accounts cannot overwrite each other's request credentials or native selected-thread status. Global native account state is not thread authority. |
| `NAC-005` Demand and lease | Request exact provider, audience, purpose, scopes, resource, units and required amount. A bounded lease records immutable grant/generation, account, route generation and binding authority; expiry never exceeds provider, custody or source authorization expiry. Expired or mismatched materialization fails before decryption. |
| `NAC-006` Credential boundary | Only trusted adapter channels materialize the narrowly scoped access credential needed by the native protocol. No refresh token, secret, provider account identifier or unknown secret-bearing field enters public metadata, argv, logs or evidence. Private native routing may require provider account identifiers. |
| `NAC-007` Compatibility and capacity | Select technically compatible accounts by default, subject to explicit policy and independent lifecycle/entitlement/grant states. Keep compatible routes sticky. Compare only matching provider/issuer, resources, units, scopes and windows; shared quota buckets count once. Expose observation provenance, age and incompleteness. Unknown capacity is not invented readiness or fresh unavailability. |
| `NAC-008` Acceptance fence | Before every request retain acceptance state and request identity. Only a proven pre-acceptance rejection may authorize substitution. Once accepted, or when acceptance is unknown, never replay, resample or repeat tool execution. Stream error, unexpected EOF, cancellation, tool-drain error and transport ambiguity cannot reopen this fence. |
| `NAC-009` Bounded alternate | A verified safe rejection can obtain at most one alternate for the same immutable demand/request. Exclude the rejected account; report before native error presentation. Exhaustion returns an honest native failure. No independent HTTP/outer retry layer may bypass the budget. |
| `NAC-010` Context portability | Rebuild only from inspectable native retained context. Never forward account-bound encrypted reasoning, encrypted tool arguments, compaction state or uploaded-file IDs across accounts without separate portability evidence. Initial adoption must also reject unproven opaque authority. Same-account credential-generation changes may retain opaque history while invalidating transport. |
| `NAC-011` Route invalidation | Account/generation changes invalidate account-bound connections, cached transports and routing affinity. Account substitution additionally clears incremental references and reconstructs portable input. Keep transcript, tool results and approvals; never rerun tools to reconstruct context. |
| `NAC-012` Renewal ownership | Each adopted refresh lineage has one verified writer. Native/browser import does not transfer ownership. Adoption requires verified identity, explicit authority, native-writer retirement acknowledgment and crash reconciliation. Ambiguous rotation is quarantined; spent refresh tokens are never restored. Access-only refresh exclusion does not prove adoption or renewal. |
| `NAC-013` Terminal cleanup | Report acceptance, completion, rejection or abandonment with the held lease authority. Cancellation belongs to the operation owner. Clock expiry never proves native work finished; retain in-flight authority until an explicit terminal report, including after preparation failure or early EOF. Abandonment releases resources without permitting replay. |
| `NAC-014` Safe unregister | Detach only after native acknowledgment of idle, inspectable portable state and drained authority. Retain custody/configuration when safe detach is unavailable. Protect delayed releases against newer bindings with current lease authority. Recheck native input before restoring ambient auth to catch context arriving after the control check. |
| `NAC-015` Lifecycle separation | Pause stops new admission; drain lets already accepted work finish; source disappearance detaches while retaining independently valid grants/history; explicit source disconnect ends that authorization. Forget removes retained secrets and records a re-enrollment tombstone. Upstream revoke is distinct. Account resume restores eligibility subject to all remaining checks, not native request replay. |
| `NAC-016` Restore and remove | Restore only owned integration settings, preserving later user edits and native stores. Conflicts return a repair condition. Removing a client does not stop the daemon; disconnect, integration removal and uninstall have explicit effects. |
| `NAC-017` Redacted status | Status/registration acknowledgments do not acquire credentials or make provider calls. Cached observations bind to account, thread and generation, expose timestamps and stale/unknown values, and cannot overwrite newer routes. Native process-global account APIs cannot pretend to represent a broker-managed thread. |
| `NAC-018` Golden conformance | Record ordinary launch, native resume, permitted existing attachment, concurrent isolation, provider-originated pre-acceptance rejection, compatible alternate admission, unchanged process identity, preserved native history/tools/approvals, accepted-stream fencing and no routine prompts against the exact application build. Local fixtures and previous releases cannot satisfy this ID. |

## Current request lifecycle

The [terminal-removal projection](../../src/terminal_removal.zig) retains its
historical sixteen pure `ecbadbac` predicates. Additive engine exposure through
`reliability.lifecycle.terminal_removal` passed in
`8debe108-b689-4500-9b85-91ed0f77f3ba`: 250 target cases including eight local
removal/imported engine cases and formatting, zero exits/empty descendants.
See [resume evidence](../tracker-updates/integrated-delivery-resume-2026-10-05.json)
and the [session record](../agent-notes/2026-10-05-sess-omux-integrated-delivery.md).
Actor forget/replay/restart and SQLite-denied admission, synthetic socket-native
removal/replay/restart and lost-detach-reply pending custody are proved predicates;
final-commit-only failure and live application removal remain unproved. Retained
authority distinguishes completion, pending safe removal and unresolved work;
pending never counts as success. No new persisted schema, authority or wire
method is added. Complete denominator, window, duration and achieved SLO remain
absent; five product gates pass and six remain open.

`adapter.acquire` uses `application`, `session_id`, optional `binding_id` and
mandatory opaque `request_id`, and typed `demand`. Native adapters must supply
a request ID of 1–64 ASCII letters, digits, hyphens or underscores; there is
no session-ID fallback. A durable replay ledger binds
that ID to immutable application/session/binding/demand authority and permits
at most two attempts. Accepted, completed, abandoned or restart-unknown requests
cannot be reacquired. Expiry and TTL cleanup never recycle request authority. The bounded ledger
retains at most 4096 request identities; exhaustion fails closed and is an
operational limit, not permission to delete replay fences. The response
contains opaque `lease_handle`, account/grant handles, grant generation, route
generation and expiry. `adapter.materialize` validates held purpose/audience,
source authority, expiry and current grant generation before exposing private
access authorization. A lease cannot extend upstream validity.

`adapter.report` accepts `accepted`, `completed`, `rejected` and `abandoned`.
Completion follows acceptance; abandonment covers issued or accepted requests
and never enables another attempt. Current safe rejection requires an issued
lease, `pre_acceptance: true`, `response_started: false` and HTTP 401, 403 or
429. A 401 invalidates the held grant generation; 403/429 records bounded
resource unavailability. These are implemented classifications, not universal
proof that every provider response is replay-safe. Native conformance must
establish the rejection boundary for each exact provider/application protocol.
The handler permits one alternate with unchanged demand and excludes the
rejected account.

`adapter.releaseBinding` requires the latest `expected_lease_handle` for a
retained binding and rejects stale cleanup. Native lease history/expiry cleanup
and safe native unregister are separate obligations. Restart preserves domain
in-flight leases and marks unfinished requests unknown; lost materialization
capabilities cannot be recovered from old handles. Completion of an unknown
request requires durable acceptance acknowledgment. Unknown issued work without
that acknowledgment permits abandonment only. Expiry blocks credential access
but cannot release uncertain work to permit forget, detach or route changes. Releasing a binding is not
account deletion, grant revocation or permission to replay.

## Codex owner and candidate boundaries

The current Omux source implements bounded authenticated owner discovery within
one selected native integration context. It enumerates immediate publication
hints, retains descriptor/path custody and probes each owner V2 Unix
`SOCK_SEQPACKET` endpoint with fresh peer evidence under one shared deadline.
Publication names and paths are observations, never native authority. Unsafe,
changed, ambiguous or oversized inventories refuse; no partial list may conceal
missing preparation. An explicitly supplied endpoint remains a manual
compatibility override, not automatic selected-context discovery proof.

These new Omux paths still require their own installed discovery and ordinary
CLI/TUI/resume receipts. The preserved164-change candidate and exact
`4b0fcf36` provider-free installed app-server pair retain their explicit-endpoint,
initialized zero-turn history and zero-acquire removal limits. Their unavailable
automatic discovery and ordinary launch/resume predicates describe that frozen
pair, not the later source implementation. The
[separate native owner candidate](../../integrations/codex-owner-candidate/README.md)
and [installed interoperability evidence](../implementation/native-interop-evidence-2026-10-04.md)
retain those exact source and runtime epochs. The
[discovery/resume sprint](../plans/omux-native-discovery-resume-sprint-2026-10-04.md)
records a separate immutable candidate/SDK epoch for exact read-only attachment
status. Epoch `cd8c87d7-85f4-4c41-836c-18d8a6f7585c` passed exactly two local Rust
predicates; it did not close installed discovery or ordinary launch/resume.
Packaging, capability flags and local
owner fixtures do not establish stock Codex support or live continuity.
`native_support` remains false; `hook_compatible` only reports observed
experimental hook compatibility, not a support promotion. R-N13 records this
current-source contract update without adding execution evidence.

`owner/capabilities` and `owner/threads` are read-only. Their outer
`protocolVersion` is 2; the nested hook capability schema deliberately retains
`protocol_version: 1` and the six required boolean flags below. Discovery
compares owner ID, process nonce, endpoint generation and fresh peer witness
across capability and thread replies on the same captured channel. Thread
rows contain bounded IDs and nonzero canonical decimal generation strings.
Reserved attachment-generation metadata cannot admit custody. Lists have a
1,024-row ceiling and a 64 KiB encoded packet limit; oversize input refuses
before effects, with no pagination promised for this slice.

Automatic discovery returns `owners`, with `owner_id`, `process_nonce`,
`endpoint_generation`, `owner_endpoint`, `native_version`, `support` and `threads`.
Each thread has `thread_id`, `thread_instance_generation`, diagnostic
`attachment_generation` and nullable `native_ref`. Only an exact currently
committed attachment matching the fresh observation can populate `native_ref`.
Duplicate native instance generations or ambiguous owner identities refuse.
The complete public JSON-RPC discovery reply must fit 64 KiB, including its ID
and envelope; per-endpoint packet success does not establish aggregate fit.
The native home may be owned and readable, but cannot be group/other writable;
publication directories remain 0700 and sockets 0600 with no alias traversal.

### Qualified stdin-RPC selection

The generated method catalog remains a name/summary/channel catalog, not formal
per-method parameter schemas. The following contract records the implemented
fields. `omux integration discover [codex [config-path]]` selects a context.
The typed `integration attach`/`detach` commands cannot supply an owner selector
or derive a committed reference; their usage listings do not promise success.
Use stdin RPC or native controls for qualified operations.
An explicit endpoint/thread compatibility request remains a separate manual
path; it cannot stand in for selection from the selected-context inventory.
Supplying any owner-selector field requires all four selector fields below.

Read the context and choose one owner and one thread from the same response:

```sh
omux rpc integrations.discover - <<'JSON'
{"adapter":"codex","config_path":"<selected absolute config path>"}
JSON
```

Replace the placeholders below with JSON-escaped values from that exact
`result.owners[N]` and its `threads[M]`. Keep returned canonical generation
strings unchanged. `config_path` must select that owner's native context; it
cannot redirect an active installation away from its retained config.

```sh
omux rpc integrations.attach - <<'JSON'
{
  "adapter": "codex",
  "config_path": "<same selected absolute config path>",
  "owner_endpoint": "<owners[N].owner_endpoint>",
  "owner_id": "<owners[N].owner_id>",
  "process_nonce": "<owners[N].process_nonce>",
  "endpoint_generation": "<owners[N].endpoint_generation>",
  "thread_id": "<owners[N].threads[M].thread_id>",
  "thread_instance_generation": "<owners[N].threads[M].thread_instance_generation>"
}
JSON
```

The daemon rechecks the selected context, publication, fresh peer, full selector,
original registry, adapter epoch and revision before admission. It never chooses
a process from a bare thread ID. Discovery's diagnostic attachment generation
does not become an admission generation. Successful attachment returns the
actual committed `native_ref`; retain that entire object for later detach.

For detach, paste the exact non-null committed object returned by successful
attachment, or the exact current committed discovery `native_ref`, into the
shell variable below. Do not construct it from diagnostic fields, invent an
epoch/generation or reuse another thread's object. The object contains opaque
identity and canonical generation strings, never credentials.

```sh
committed_native_ref='<paste the complete returned native_ref JSON object>'
omux rpc integrations.detach - <<JSON
{
  "adapter": "codex",
  "owner_endpoint": "<same returned owner_endpoint>",
  "thread_id": "<same selected thread_id>",
  "native_ref": $committed_native_ref
}
JSON
```

Detach validates the retained owner/reference, fresh peer and safe native context.
An optional full selector uses the same `owner_id`, `process_nonce`,
`endpoint_generation` and `thread_instance_generation` fields as attach and must
match the committed reference. The CLI supplies a new stable `operation_id` and
current `expected_revision` when omitted; callers may instead supply their own
64-character lowercase hexadecimal operation ID and actual current revision.
After a lost reply, query `operation.status` with that original operation ID;
do not repeat the command with a fresh ID or infer retirement from absence.
No placeholder request is literal wire authority: fill only actual returned
identity/context values. These templates declare source behavior and do not
establish installed CLI, native resume or live-provider acceptance.

`owner/identify` establishes read-only native process/thread attribution.
`adapter.owner.register` requires fresh socket-derived proof before grant
acquisition or thread readiness. The daemon persists pending custody before
the `owner/register` effect. Register and unregister acknowledgments echo the
exact owner ID, process nonce, adapter epoch, endpoint generation, thread
instance generation, attachment generation, thread ID and stable operation ID.
The four generations are canonical nonzero decimal u64 strings. Registration
also supplies private `brokerSocket` and `capabilityPath` metadata; capability
bytes do not cross this endpoint.

`owner/announce` invokes the actual native registration producer. Its reply
alone cannot complete a control mutation: the actor must match the committed
inner registration. `owner/unregister` uses a new stable detach operation and
has no release callback. Saved witness metadata cannot recreate live peer
proof, and restart cannot authorize replay of accepted or uncertain work.

### Preserved protocol-1 candidate

The [candidate README](../../integrations/codex-upstream/README.md),
[manifest](../../integrations/codex-upstream/manifest.json) and
[validation record](../../integrations/codex-upstream/validation.json) bind the
patch to official `rust-v0.157.0`, commit
`00c972ed5d6ff6499317fd41b7f23605b8e6850d`. The manifest remains
`status: upstream-patch-candidate`, `native_support: false`. Its local compile,
protocol and synthetic receipts establish only their stated predicates.
Live continuity, applicable opaque-context portability and delivery qualification
remain unpassed promotion gates. Upstream acceptance remains required if this
candidate is delivered upstream. A locally patched evaluation binary establishes
neither a supported maintained-modification distribution nor live continuity.

The preserved candidate uses WebSocket text frames over its advertised Unix
socket, not raw JSONL. That native extension negotiates protocol 1 and requires
`late_thread_binding`, `per_request_auth`, `exclusive_refresh_owner`,
`preacceptance_failure`, `account_transport_invalidation` and
`native_context_reconstruction`. These flags describe conditional hook
mechanisms; they do not prove that a particular history is portable.

Its protocol-1 registration supplies `threadId`, `bindingId`, `brokerSocket`,
`capabilityPath` and `protocolVersion`. The response's
`refreshOwnershipAcknowledged` means bound model requests use access tokens
only and cannot invoke native refresh. It does **not** adopt the native refresh
lineage. Current imported grants remain externally owned; no renewal API is
implemented. Capability material stays on the private adapter channel.

The candidate invokes acquire/materialize/report for native model HTTP/SSE at
the fixed official endpoint. It excludes ambient authorization, account routing,
cookies and turn affinity. Explicit pre-stream 401/403/429 may obtain one
alternate; HTTP and outer Responses retries are fenced for broker requests.
Opaque content blocks initial adoption or cross-account substitution; a
same-account generation change is permitted to retain opaque history while
clearing account transport. No cross-account encrypted reasoning/tool arguments,
compaction or file-ID portability is asserted.

Its protocol-1 unregister uses `threadId` and optional `releaseBinding` (native default
true). Native callers schedule bounded daemon release with the expected latest
lease. Omux-coordinated disconnect uses `releaseBinding: false`: the daemon owns
release after acknowledgment, avoiding reentrant callbacks while its writer
awaits the native response. Idle detach rejects opaque/uninspectable histories.
Successful detach retains a native reentry fence until actual next-request
input passes the portability check, preventing racing final context from
escaping into ambient authorization.

Adoption makes shared model discovery descriptive and remote plugins local-only
until process exit, including unbound threads sharing those managers. Unsupported
ancillary authorization fails closed. An already dispatched native request
cannot be recalled. A cancelled Apps subscription lacks terminal acknowledgment
and retains its authorization fence until exit; late attachment may remain
unavailable. A capability response cannot erase these restrictions.

## Adapter proof matrix

Rows describe current source and recorded evidence, not new executions. No
adapter has successor live continuity proof.

| Adapter and exact boundary | Local source / recorded proof | Native and live gates still required | Claim boundary |
| --- | --- | --- | --- |
| Codex stock application | Bounded capability discovery and unsupported-handshake fixtures in `src/integrations/codex.zig` / `native_probe.zig` | `NAC-001`–`NAC-018` against an accepted compatible native build | Stock general account/app-server RPCs cannot enable handoff or attachment |
| Codex `rust-v0.157.0` preserved protocol-1 candidate | Manifest-bound patch has 17 broker predicates, eight-target compilation and complete post-build source verification in the recorded evening epoch. The 55 broker/318 protocol cases belong to its historical patch; evening schema-writer actions each filter out 318 tests. Omux runtime binding/request fixtures retain their separate source epochs. | Qualified delivery (upstream acceptance if delivered upstream); ordinary launch/resume and existing attachment; live rejection/handoff and concurrent native state; opaque-context limits (`NAC-003`, `NAC-008`–`NAC-012`, `NAC-018`) | Preserved candidate only; `native_support=false`; no qualified maintained modification or live promotion |
| Codex `rust-v0.157.0` separate owner-V2 candidate, commit `00c972ed5d6ff6499317fd41b7f23605b8e6850d` plus frozen164-change patch | Own native producer, schema, complete-source and eight-production-label receipts in [owner evidence](../implementation/native-owner-evidence-2026-10-04.md). Exact optimized runtime packaging and fresh Sting installed app-server setup/registration/zero-acquire removal passed in [interop evidence](../implementation/native-interop-evidence-2026-10-04.md), with genuine metadata initialization and unchanged zero-turn history. | Ordinary CLI/TUI launch, native resume, existing-work attachment, accepted nonempty history, foreign-process attacks, lost ACKs and live provider handoff remain unproved. Automatic endpoint discovery and daemon replacement are unavailable. | Experimental candidate only; `native_support=false`; preserved protocol-1 counts and earlier failed installed epochs do not certify this exact pair |
| Claude Code | `src/integrations/claude.zig` reversible endpoint edit and activation-prerequisite fixtures | Authenticated request proxy, scoped credentials, native renewal retirement, verified safe boundary, exact version; existing-process native hook (`NAC-001`–`NAC-018`) | Configuration foundation only; startup endpoint settings cannot attach an existing process |
| Git HTTPS / GitHub | `src/integrations/git.zig` helper parsing/scoping; daemon `gitGet`/`gitErase`; recorded synthetic host/path/user and rejection fixtures | Exact Git version/config, native helper invocation, verified remote repository permissions and ordinary operations; removal/restoration (`NAC-001`, `NAC-005`–`NAC-007`, `NAC-015`–`NAC-016`) | Narrow `https://github.com` repository credential boundary; no rich session attachment, upload replay or in-request recovery claim |
| OpenCode | No current adapter in the catalog or native conformance evidence | Separate native capability investigation and version-bound contract before implementation | Deferred; no inferred support from compatible APIs |

Git helper `get/store/erase` are native credential protocol operations, not the
common rich-session protocol. The current daemon requires GitHub HTTPS and a
validated repository path, filters verified usernames, and returns native helper
fallback when no compatible account remains. `erase` only cools a matching
current rejected credential/context; missing or stale secrets do not revoke
accounts or invalidate unrelated repositories. Helper invocation is its safe
boundary. No claim is made for SSH, arbitrary hosts or repeating an accepted
Git request.

## Evidence and promotion

Selected-runtime authority and live executable attribution are separate
requirements. The current Codex package already binds source/producer inputs,
upstream commit and packaged executable/runtime digests. Its missing installed
selection must derive from verified artifact/ownership evidence and bind
channel/target, manifest/archive/source/producer digests, backend/loader
identities, installation transaction and adapter epoch. It must refuse
selection drift during mutation/recovery while preserving native custody and
history. No selection wire method or registry migration is implemented here.

The portable Codex launcher explicitly executes a bundled loader. A hash of
`/proc/PID/exe` alone cannot be presumed to attest its backend; the actual launch
profile requires a version-bound proof. Existing fresh socket-derived peer
evidence establishes process incarnation and message writer, not executable
identity. Peer-claimed version/digest fields and a persisted selection do not
close that gap. See the [delivery audit](../../integrations/codex-adapter-delivery/README.md)
and its primary kernel reference. Experimental conformance may retain exact
fixture-launched artifact provenance; it cannot silently become runtime delivery
qualification or continuity support.

For every accepted ID, record source commit/dirty state, platform, native
application version/commit/artifact digest, Omux artifact digest, test target,
Bazel invocation receipt, predicate, outcome and remaining restrictions. Use
redacted opaque identities, never raw account identifiers, credentials or PII
captures. Distinguish source implementation, local synthetic checks, native
conformance and live-provider evidence. Mark inapplicable rich-session IDs
explicitly for Git rather than granting a broad continuity claim.

All executable validation, generators and packaging run through Bazel/Bazelisk
with locked Nix inputs. Reading this contract and source review are not executable
proof. Live provider work requires its own authorized, exact-build evaluation;
none is performed by declaring this contract. Capability promotion must update
source metadata and committed evidence together; website/API rendering, an
upstream patch schema or a passing fixture cannot promote support.
