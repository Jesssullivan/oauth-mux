# Dedicated account and native evaluation matrix — 2026-10-04

Status: planned, experimental and unshipped. The user confirmed resource
availability and subsequently identified two Codex account candidates, recorded
only as `codex-home` and `codex-startup`. Their provider identities and technical
compatibility remain unverified; exact profile resources and budgets remain
deferred. This record authorizes preparation, not provider requests, credential
collection, personal-vault access or service activation. It records no new
execution receipt, human appointment, release claim or contractual SLA.

Authority remains the [native reset](omux-native-account-lifecycle-reset-2026-10-02.md),
[user stories](../product/user-stories.md), [adapter contract](../spec/native-adapter-contract.md),
[custody contract](../spec/native-lifecycle-and-custody.md) and
[support definitions](../product/support-and-completeness.md). Existing evidence
retains its original source, artifact and predicate scope.

## Current boundary and selected outcomes

The [installed interoperability checkpoint](../implementation/native-interop-evidence-2026-10-04.md)
passed genuine candidate registration and zero-acquire removal with preserved,
initialized zero-turn native history. It did not prove accepted user turns,
nonempty history, ordinary CLI/TUI resume or live handoff. Stock Codex lacks the
required native hook. The separate [owner candidate](../../integrations/codex-owner-candidate/README.md)
and [runtime package](../../integrations/codex-owner-runtime/README.md) remain
version-bound research inputs with `native_support:false`; Omux ships no Codex
fork and cannot promote stock support through candidate evaluation.

The selected Codex evaluation is access-only use of two independently verified,
compatible accounts through a genuine native owner. Imported grants remain
externally owned. Refresh adoption, ownership transfer and provider renewal are
separate implementation and evaluation gates. Import, a capability flag or
access-token refresh exclusion does not complete those gates.

Git HTTPS/GitHub is the requested non-LLM lane. Its implemented boundary is
one-time reversible credential-helper setup followed by ordinary Git commands.
It is suitable for testing account selection at Git's native credential boundary;
it does not have Codex's rich-session attachment or same-process transcript
contract. SSH, arbitrary hosts and accepted-request/upload replay are outside
this scope. Real remote permission and recovery behavior remain unproved.

## Five-hour and ten-hour checkpoints

These are coordinated checkpoints, not delivery guarantees. Named account
candidates do not fill in their verified identities, permitted operations or spending limits.
Live portions remain pending until the applicable intake is recorded.

| Ticket shape and acceptance references | Five-hour provider-free result | Ten-hour dedicated result, conditional on intake |
| --- | --- | --- |
| EVAL-CODEX-ENTRY: ordinary command and native resume preserve the user's native session authority; US-LAUNCH-01, NAC-001/002 | Exact candidate/platform input and ordinary CLI/TUI/endpoint discovery or explicit setup contract; declared installed conformance and honest unsupported cases | Actual ordinary launch and native resume with compatible authorization, no Omux wrapper, alternate home or relaunch presented as continuity |
| EVAL-CODEX-ENROLL: authorize sources once and independently verify compatible accounts; US-SOURCE-01, LC-01/05/06 | Authorized-source, expiry, conflict, encrypted custody and unavailable-key predicates; review the fixed provider reader and exact grant shape | Two verified account routes for the same declared model/resource/workspace, with known audience, scopes, expiry and external renewal owner |
| EVAL-CODEX-HANDOFF: a real safe rejection substitutes authorization in the unchanged native process; US-HANDOFF-01, NAC-005–011/018 | Declared request/acceptance/alternate harness; genuine native wire and private fault-fixture tests; frozen redacted receipt contract | Provider-originated pre-acceptance failure on A, compatible acceptance on B, unchanged native process incarnation/session and preserved prior transcript, tool results and approvals; at most one alternate |
| EVAL-CODEX-ACCEPTED: accepted or unknown work cannot replay; US-NOREPLAY-01, NAC-008/013/014 | Native request/removal barriers, lost-report/ACK and uncertain-state predicates; any fake-provider result explicitly stays synthetic | Actual accepted nonempty native history and one harmless owned tool effect; bounded failure/cancellation or removal retains authority until the original authorized terminal outcome, without repeated tool execution |
| EVAL-GIT-HTTPS: configure once and use ordinary Git with verified remote permissions; NAC-001/005–007/015/016 | Actual installed helper/configuration and stdin protocol predicates, username/repository scope, stale erase refusal and owned restoration | Ordinary GitHub HTTPS read operations use the genuine installed helper and compatible grants; local pause or a real scoped credential rejection is classified at the next verified helper boundary; no unsupported silent in-command recovery promise |
| EVAL-RESOURCE: exact resource observations remain scoped and fresh; US-RESOURCE-01/FRESHNESS-01, NAC-007/017 | Units/window/provenance/unknown/shared-bucket and local-admission predicates; review concrete readers | Actual chosen provider observation and rejection semantics, with observed age and declared limits; no additive total from unknown bucket identities |
| EVAL-RENEWAL: imported authority cannot create a second renewal writer; US-RENEWAL-01, NAC-012, LC-07 | Explicit adoption/retirement/crash-reconciliation design and current fail-closed boundaries | Separate future implementation and provider gate; access-only handoff cannot mark this ticket complete |

Each ticket records its user outcome, stable acceptance references, exact scope,
dependencies, resource intake, declared Bazel action, source/artifact tuple,
predicate, result and exclusions. Proposed ticket keys above are planning labels,
not new tracker issues or executable target names.

The dependency order is qualified host and exact artifacts, native setup and
entrypoint contract, authorized source and verified grants, then provider
evaluation. Request acceptance and portable context must be verified before
account substitution. Provider-free gates can proceed while resource labels and
budgets are pending. A failed native prerequisite produces a bounded missing
capability result; it does not justify using a mock as live evidence.

## Concrete resource intake

Keep this intake credential-free. Use symbolic account/source/repository labels
until the user supplies nonsecret labels; do not infer them from names, emails,
existing login state or account balances. Record approval scope locally before
opening a source or issuing provider requests.

| Intake field | Required disposition |
| --- | --- |
| Host, platform and application | Exact qualified OS/architecture, Omux artifact, native candidate or stock build, Git version and intended ordinary launch/resume modes |
| Account and source labels | Codex candidates `codex-home` and `codex-startup` are user-declared; no addresses are retained here. Provider identity/account type, compatible entitlements, authorized source kind and finite read authority remain unverified. GitHub route labels remain unset. |
| Compatible operation | Exact Codex model/resource/workspace or GitHub HTTPS repository, entitlement and permission scope; both routes must independently permit the same operation |
| Secret source | Locally approved narrow native store or private explicit input, owner-only directory and mode-0600 file/descriptor where applicable; secret material travels only through the implemented stdin/private channel into encrypted custody |
| Validity and renewal | Provider, source and custody expiry; external writer and any competing native enrollment/renewal work; access-only evaluation ends before the earliest applicable expiry |
| Provider budget | Maximum requests, model tokens, elapsed time and cost; Git transfer bytes/rate allowance; identity and background observation reads count too; all values currently remain unset |
| Rejection condition | Approved real pre-acceptance failure mechanism or already available constrained account; no implicit quota burn, token revocation, auth mutation or spending escalation |
| History and tools | Private disposable nonpersonal native session/workspace; harmless tool effect and permitted approval interaction; authorized inspection of retained native history |
| Evidence and cleanup | Private receipt destination, redacted publication scope, exact owned paths/processes and desired retain/remove disposition; never sweep prior workspaces or unrelated services |

The existing CLI accepts `source connect -`, `enroll <source_id>` and
`rpc <method> -` parameters through stdin in [main.zig](../../src/main.zig).
These are interface facts, not commands to run from this plan. Credentials never
belong in chat, argv, environment variables, repository fixtures or diagnostics.
An authorized secure source is not permission to enumerate other credentials or
export a personal vault. Authentication factors remain provider/user enrollment
interaction, not stored grants. Source labels and native account hints cannot
replace independent identity verification.

An execution-specific declaration must bind the approved intake to the exact
action and retain finite time/resource limits. Existing isolated Secret Service
and private fixtures do not authorize activating a personal session or service.
Production browser exports remain disabled pending their separate provider proof.

## Codex access-only live acceptance

1. Qualify the selected host's genuine peer evidence and bind exact Omux/native
   source, patch, producer, runtime and artifact identities. Require the actual
   V2 owner channel and all native hook prerequisites; a declaration is not proof.
2. Authorize and independently verify two accounts from the declared local
   sources. Check provider/issuer, tenant, audience, request/account-read purposes,
   scopes, entitlement, model/resource and all expiries. Retain opaque handles;
   never publish subjects, provider account IDs or credentials.
3. Install reversibly, launch normally and separately exercise native resume.
   Genuine registration/ACK and committed original NativeRef must precede request
   authority. Keep the original process alive throughout each handoff opportunity.
4. Establish actual accepted nonempty history and a harmless owned tool effect.
   Record private baseline evidence for native process incarnation, session,
   retained turns, tool results and approvals. Zero-turn metadata initialization
   and a fake provider's accepted flag do not satisfy this step.
5. Observe a genuine provider rejection before acceptance on A and the exact
   immutable demand's acceptance on B. Current daemon classification permits
   issued requests with HTTP 401/403/429, `pre_acceptance:true` and
   `response_started:false`; exact provider/native evidence must establish safety.
   A status code by itself is insufficient. Accepted, streamed or unknown work
   never receives another attempt; the same request has at most two attempts.
6. Confirm unchanged process incarnation and session/store authority, preserved
   existing transcript/tool/approval entries and legitimate append-only new work.
   Whole-history bytes may change as new turns append; preservation is not an
   unchanged-file-hash assertion during active work. Clear account-bound transport
   and incremental references. Unportable reasoning, compaction, encrypted tool
   arguments or uploads refuse substitution rather than replaying tools.
7. Exercise bounded terminal cleanup and truthful no-alternative behavior.
   Unknown completion, expiry or daemon restart cannot reopen request authority.
   New admission after unresolved native recovery remains unavailable without its
   own implemented/proved reconciliation contract. Removal requires original
   native ACKs, retained request fences and verified owned configuration restoration.

Completion is a named access-only candidate/provider/resource tuple with all
applicable steps observed, redacted evidence retained and claims reconciled. It
does not complete stock support, refresh continuity, arbitrary tools/uploads,
Darwin, browser acquisition or speculative mid-stream recovery.

## Git HTTPS/GitHub live acceptance

[git.zig](../../src/integrations/git.zig) appends an owned helper block and sets
`useHttpPath=true` for the supported GitHub origin. It preserves existing helper
order and unrelated configuration. An earlier complete helper can satisfy Git
before Omux; installation does not imply exclusive routing. Prove the installed
Omux helper was actually consulted before attributing remote success to it.

Use normal Git commands after the one-time setup, with credentials supplied by
the native helper protocol rather than URL/argv/environment. Verify actual
GitHub HTTPS repository permissions with a bounded read-only operation in an
owned workspace. Record the exact remote scope privately and publish only its
evaluation alias. No write, push or upstream revocation is implicit.

The daemon validates host, repository path and any requested verified username.
A username pinned by Git or existing configuration can make another account
incompatible; never override it to manufacture cross-account success. Actual
`get`/`erase` behavior must be observed for the chosen Git version. `store` does
not import authority or transfer renewal ownership. A rejection cools only a
matching current credential/generation and repository context; missing/stale
erase data must not revoke an account or affect unrelated repositories.

Evaluate local pause followed by the next ordinary credential boundary, and
separately a real current-credential rejection if its mechanism is explicitly
authorized. Record whether native Git retries safely, or whether a later ordinary
operation obtains the alternative. Do not turn that distinction into a claim of
silent recovery inside every command. A fake helper/provider remains synthetic,
and an accepted request, pack transfer or upload cannot be blindly replayed.

Verify native fallback when no compatible route exists, repository/username
isolation, encrypted custody, and reversible owned configuration removal with
unrelated later edits preserved. Git's applicable acceptance does not require a
Codex transcript or rich-session attachment, and cannot prove Codex handoff.

## Resource observations, receipts and reliability

The current [observer](../../src/observer.zig) verifies Codex WHAM user/workspace
identity before ingesting usage and represents included-use percentages and
provider decisions separately. WHAM supplies no proven shared-bucket identity or
percentage denominator suitable for additive account totals; unknown buckets
stay unknown. GitHub core API rate capacity is separate from repository transport
permission, bandwidth or write entitlement. Do not present one as another.

Record exact resource kind/target/unit/scope/window, observation provenance and
age, independent quota-bucket relationships, grant readiness and whole-snapshot
admission. Healthy quota cannot override local admission limits, unavailable
custody or unsafe native context. Status and health reads do not authorize
provider probes; authorized background account-read polling has its own budget.

All builds, tests, generators, packages and evaluation executables use locked
Nix/Bazel inputs. Existing `//delivery:installed_native_interop_test`,
`//delivery:installed_custody_test`, `//:native_peer_test`,
`//:native_peer_bridge_test`, `//:git_test` and `//:engine_acceptance_test` retain
their stated predicates. They are not live evaluation targets by implication.
Any new real-provider action needs declared inputs, finite operation/time bounds,
its approved secure resource source and an exact independent receipt.

Receipts bind platform/application/provider tuple, immutable source and artifact
digests, invocation identity, observed opportunities, bounded phase/return codes,
native-state preservation, credential/renewal exclusions and owned cleanup.
Separate fixtures, installed native conformance and live provider evidence. Keep
failed epochs and missing gates; no new result inherits an old proof. Do not
capture raw credentials, private provider replies, personal prompts, native
history, account IDs, email addresses or PII screenshots in shared evidence.

Use the [service objectives](../reliability/service-objectives.md) for measurement:
eligible admission, readiness coverage, native integrity, custody and freshness
have separate denominators. Report failures, exclusions, unobserved work,
latencies and sample counts; zero opportunities is unmeasured. A five/ten-hour
evaluation is provisional, not a 28-day availability baseline. Integrity,
no-replay and secret-custody requirements have zero breach budget. No achieved
SLO, staffed response coverage, SLA or service credit is promised by this matrix.
