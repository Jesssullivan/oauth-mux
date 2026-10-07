# Native operations runbook

This runbook covers the experimental native reset, not historical wrapper-era
commands. There is no deployed SLA. Adopted design and measurement targets,
severity tiers and stable acceptance IDs are in
[service objectives](../reliability/service-objectives.md); their achievement
remains unmeasured and future staffed response commitments remain proposed.
The current [CLI catalog](../../src/reference.zig),
[dispatcher](../../src/main.zig), [API method catalog](../../src/control.zig)
and [delivery instructions](../../delivery/README.md) are operational authority.
`omux --help` renders that source catalog; unsupported commands are not repair
procedures. All executable repository work uses locked Nix and Bazel.

## Local diagnosis

The following repository invocations inspect local metadata without initiating
provider requests; they may build their declared target first:

```sh
nix develop --command bazelisk run //:omux -- --help
nix develop --command bazelisk run //:omux -- status
nix develop --command bazelisk run //:omux -- integration status
nix develop --command bazelisk run //:omux -- usage
nix develop --command bazelisk run //:omux -- rpc system.health -
nix develop --command bazelisk run //:omux -- rpc reliability.export -
```

For the stdin RPC reads above, supply an empty JSON object (`{}`) on stdin.
Reliability export is bounded in-memory local measurement: restart clears its
history, and missing scheduled coverage remains visible. It does not prove an
achieved SLA.

Use the actual runtime state directory consistently; the CLI supports
`--state-dir <absolute-path>`. Do not substitute installation ownership state
for the runtime database directory. Follow XDG paths on Linux and Library paths
on macOS. A supplied Linux `XDG_RUNTIME_DIR` must already be safe and owner-only;
an invalid supplied path fails rather than falling back. When absent, sockets
use state/run. Healthy transport does not establish account eligibility or live
handoff support. Check `protocol_version`, `revision`, `captured_at` and
`custody_available`, then source/account/grant lifecycle, observations and
`capacity.complete`/`unknown_buckets`. Raw snapshots may contain personal labels
and paths: inspect locally and prepare only a scrubbed report.

## Daemon absent or custody unavailable

Distinguish connection failure, version mismatch, private-path/peer rejection,
startup vault error and `ServiceBusy`/timeout. Record the typed error, elapsed
time and intended operation interval. A closed UI should not stop the daemon.
Check the user's service configuration and the exact installed artifact against
the ownership manifest. Delivery installs service templates without activating
them; no automatic service repair/activation API exists. Platform activation
requires its declared execution path and explicit operator action. This runbook
does not invent a Bazel service-manager target.

For a locked vault, unlock the existing macOS Keychain or Linux Secret Service
through its native user interface, then retry local startup through the declared
platform path. For an unavailable/missing key with an existing database, retain
the database and vault identity and escalate custody recovery. Never delete the
database, regenerate a wrapping key, copy plaintext grants or put keys in argv.
For permanent key loss, preserve the failed installation and offer explicitly
authorized fresh enrollment into a separate database/vault namespace. Fresh
custody is new authority, not replacement-key recovery of the unreadable database.
Never import stale refresh generations or clear tombstones to present recovery
as success. This policy does not imply an implemented fresh-custody command.
Older version-1 custody databases require explicit migration and fail closed;
do not copy a backup to seed fresh recovery authority. SQLite-only stale restore
is fenced by a separate authenticated checkpoint. Coordinated rollback of both
files and vault loss remain outside that demonstrated protection.
There is no daemon-level `repair` endpoint: `omux repair` acts on an account.
A daemon restart may restore local service but is not proof of routine
same-process account handoff; never restart the application to claim continuity.

## Capacity unknown or accounts ineligible

Inspect observation `observed_at`, `expires_at`, status, provenance, exact scope,
unit and window. Incomplete totals cannot establish route readiness. The reader
spaces authorized polls by 60 s and ordinarily expires observations at 120 s;
timeouts, queue backpressure, missing account-read permission and provider
schema failures can leave capacity unknown. Do not convert unknown into zero or
ready, sum incompatible windows, or count shared quota buckets twice.

Check paused/draining/forgotten account state, grant validity and source
authorization separately. A browser-bound grant requires its browser context;
an imported grant does not transfer renewal ownership. Do not retry a spent
refresh token or restore an ambiguous rotation. `native_unsupported` requires a
verified hook and exact-version evidence; route-election fixtures do not repair
that missing capability. Health diagnosis must not trigger live inference or
synthetic admission. Provider reads/reconciliation require a deliberate action
within the authorized source, and their consumption must be recorded.

## Authorized reconciliation and account repair

After identifying a supported source problem, the implemented CLI permits:

```sh
nix develop --command bazelisk run //:omux -- source reconcile <opaque-source-id>
nix develop --command bazelisk run //:omux -- repair <opaque-account-id>
```

Replace placeholders locally; never paste real identifiers into evidence.
These are mutations and may contact a provider. `repair.start` reconciles already
authorized sources and can return `verifying_identity` with operation IDs,
`reconciled`, `ready`, or `needs_user` / `provider_authorization`. A returned
operation ID is not completed enrollment or recovered request capacity. Follow
`jobs` in a fresh snapshot; perform required provider authorization explicitly.
Do not assume automatic refresh adoption or a generic enrollment flow exists.
Source authorization uses `omux source connect -` with JSON on stdin containing
required `provider` and `kind`, plus optional `label` and `source_path`. Do not pass labels or source paths as
former positional arguments. Secrets for an implemented enrollment belong only on stdin, never arguments,
shell history, diagnostic output or issue attachments.

## Mutation timeout and native configuration conflict

Explicit verification has scoped historical Linux passes: `33452a55` engine/Qt
transport/setup UI and `08581f31` CLI/Qt transport/setup UI/verification/collector.
The latter overall batch failed. Experimental Linux `ef255a3e-8d6d-4bb7-a044-d9a42e20aded`
passed all twelve targets with zero controller/workload exits and empty descendants,
including live self-image/collector checks, engine timeout classification, stalled
service bridge, CLI 16, Qt installed custody/third-restart sealed replay and paired
core/browser registration. See the [exact installed setup tuple](../tracker-updates/integrated-delivery-installed-setup-2026-10-05.json).
Darwin/Swift remain unrun. Actual pinned Chromium/private-profile synthetic
service recovery passed in `c8f63b83-f9cb-4233-a01c-5d1e6f30f33d` with exit zero
and empty descendants; see the [exact Chromium tuple](../tracker-updates/integrated-delivery-chromium-2026-10-05.json).
Health, no-permission/tab boundaries, pending metadata, original-ID recovery over
browser restart, distinct disconnect and independent-source preservation passed.
Toolbar consent, permission granting, provider acquisition and native continuity
remain false. Exact-generation daemon restart passed in `fb13c1ae`; see the
[restart tuple](../tracker-updates/integrated-delivery-restart-2026-10-05.json).
Committed lost-reply recovery and manual Chromium reload/reconnect joined to that
generation remain unproved; full browser acceptance remains open.
End-to-end reliability/coverage remain unproved. Consult the
[resume ledger](../tracker-updates/integrated-delivery-resume-2026-10-05.json)
and [session record](../agent-notes/2026-10-05-sess-omux-integrated-delivery.md)
for exact target limits. `omux setup verify` issues
identified `setup.refresh`; direct RPC requires exactly `operation_id` and
`expected_revision`. Empty refresh remains diagnostic and unmeasured. The CLI
generates the ID and fills the revision through its control flow. Retain the ID;
query `operation.status` with that same ID after response loss or shutdown/restart
uncertainty. Do not reissue unknown work under a new identity. Exact replay uses
the cached result; changed intent conflicts, while busy or missing installation
selection returns a classified safe refusal. Collection timeout is immutable
`safe_refusal` / `collection_timed_out`, with null duration and all seven phases
unknown. Its dedicated refusal count is separate from verification completion.

`verification_completed` means local verification completed only. Inspect all
seven phase reasons/outcomes: artifact, service, vault, source, identity, grant,
native. Unknown/action-required phases do not become installed, enrolled or
continuity-ready. `reliability.lifecycle.setup_verification` derives bounded facts
from existing mutation authority and exposes uncertainty, old/future records and
missing timing. Timing is process-local admission-to-terminal before commit,
not end-to-end latency. The scoped Linux receipts validate their stated local
predicates, not measured coverage/SLO achievement.
Current AUTHORITY/CONTAINMENT/CHANNEL/SETUP/DELIVERY gates pass experimentally.
SPA local import/render/archive passed in `b62`, with the exact unsigned,
unpublished tuple in the [SPA receipt](../tracker-updates/integrated-delivery-spa-2026-10-05.json).
Foundation `9fc` remains overall failed despite passing scoped browser-root,
acquired-source, setup and actual staging targets. Corrected selector `d4fb`
passed 27 predicates; see the [selector receipt](../tracker-updates/integrated-delivery-selector-2026-10-05.json).
Native SDK producer `0ebaff4d` passed its first 16 objects with exit zero/empty
descendants. The [dependency tuple](../tracker-updates/integrated-delivery-native-dependencies-2026-10-05.json)
retains that dated first-16 scope. The [later verified union](../tracker-updates/integrated-delivery-native-union-2026-10-05.json)
has 305 unique verified objects, 1,410 missing and 42 unresolved dependencies;
acquisition is not compilation closure or native acceptance proof.
`bd412392` rerun was controller/workload 125 with cleanup unproved; apparent
test passes are unadmitted and cannot promote prior evidence or close a gate.
Backing-file mapping diagnostics identify the observed file behind the running
collector; they do not attest process memory or native application identity.
Joint readiness passed 248 scoped cases (six new/242 imported) in `c5d684a2`,
including owned-environment missing-receipt collection/replay/SQLite restart.
Setup verification/docs/source capture also passed; the overall fourteen-target
batch remained failed, exit 3/empty descendants, on two Yoga launch-fixture errors.
Its retained completed facts
classify exclusively as action-required before unknown before all-ready;
`unknown_phase_present` separately preserves overlapping uncertainty. Passive
polls/replay do not add attempts. The passing actual engine/restart predicate
expects zero all-ready while native readiness lacks a producer; pure all-ready
fixtures are not installation success. Denominator/installation-success flags
remain false and no gate is closed by this projection.

JSON-RPC `id` only correlates responses. Control version 2 mutations require
a stable `operation_id` and `expected_revision`; the CLI generates missing
values once for the action and preserves explicit values. After response loss,
query `operation.status` with that operation ID before repeating the action.
`started` or `indeterminate` does not authorize a fresh action ID. Mismatched
reuse and stale revisions fail closed. Cancellation names `target_operation_id`
separately from its own stable mutation ID. Native request IDs have a separate
durable replay ledger; acceptance uncertainty and daemon restart cannot reopen
accepted work. Bounded lifetime mutation and native-request ledgers retain
at most 4096 identities each; full ledgers refuse new authority. Inspect local
health capacity before planning further work; clearing fences or changing IDs
is not recovery from uncertainty. Restart preserves domain in-flight leases;
old handles with lost materialization capability cannot expose credentials.
Resolve unknown work through explicit completion only when acceptance was
durably acknowledged, otherwise through abandonment. Clock expiry cannot prove
native work finished or release its forget/detach/route-change fence.

Integration install/remove is a reversible owned-settings transaction. Inspect
`reliability.lifecycle.terminal_removal` as a retained-authority projection.
Historical pure sixteen tests retain their `ecbadbac` scope. Integrated
`8debe108-b689-4500-9b85-91ed0f77f3ba` passed 250 target cases, including eight
local removal/imported engine cases, and formatting with zero exits/empty
descendants; see the [resume ledger](../tracker-updates/integrated-delivery-resume-2026-10-05.json)
and [session record](../agent-notes/2026-10-05-sess-omux-integrated-delivery.md).
Actor forget/replay/restart, SQLite-denied admission, synthetic socket removal/
replay/restart and lost-detach-reply pending custody have scoped proof. This is
not final-commit-only failure or live application removal evidence. Pending is
not successful removal; no complete denominator, time window, duration or SLO
baseline is supplied. Inspect
`integration status` first and preserve modified/unowned settings. Removal of
Codex integration can retain custody until reachable native threads acknowledge
safe detach; wait for an idle portable context rather than forcing removal.
Do not replace a native home/session store, erase history or relaunch to simulate
repair. See [setup implementation](../../src/integrations/setup.zig) for transaction and
deadline boundaries. There is no generic configuration repair endpoint.

For package ownership conflicts, verify the archive and compare owned bytes and
modes using the [declared delivery actions](../../delivery/README.md). Installer
rollback and uninstall retain modified files and runtime custody. Do not use
uninstall, source disconnect, account forget or upstream revocation as routine
troubleshooting: these have distinct authorization and retention effects.

Home Manager owns fleet artifacts, service definitions and browser native-host
registration. Shared CLI/UI setup observes managed ownership and reports required
declarative changes rather than overwriting Nix-owned files. Verify exact extension
ID, host, channel and service after authorized activation. Core updates verify
compatibility before activation; generation rollback preserves runtime credential
generations, tombstones and replay authority. Development and release use distinct
service/host identities, sockets, state and vault namespaces.

Omux develops each application's hook and adapter; Codex integration does not
depend on an OpenAI-provided Omux hook. Diagnose exact application/adapter version
and delivery lane. Candidate tests do not prove installed launch/resume or handoff.

## Incident report and recovery verification

Use S0 immediately for custody disclosure/corruption, state loss, accepted-stream
replay or repeated tools; those failures have no error budget. Contain new
admissions at a verified boundary while preserving accepted work and evidence.
Do not replay accepted streams during recovery. S1 covers service-wide loss,
S2 scoped degradation, and S3 unsupported versions/documentation. Proposed
response times apply only to a future staffed agreement.

Record the REL-011 report fields, causal classification, recovery action and
fresh snapshot outcome. Scrub labels, paths, handles, native session IDs and all
PII. Do not attach raw databases, vault contents, tokens, cookies, HTTP bodies
or screenshots of accounts. Recovery checks inspect local health first; a live
provider or native continuity check is a separate authorized evidence gate.
Record unrun platform/vault/native gates plainly and never call synthetic success
a restored SLA. Scheduled metrics coverage, durable history, paging, service activation verification and
live support promotion remain REL-009 through REL-012 acceptance work.

Installed lifecycle reports also apply REL-013 through REL-019: record phase,
completed user outcome or classified refusal, local-work and total elapsed time,
explicit user/provider waits, readiness coverage and exact deployment provenance.
A timely refusal is not successful install, enrollment, renewal, launch/resume,
update or removal. Preserve restart-spanning redacted baseline receipts; the
current in-memory export cannot supply durable coverage.

`reliability.lifecycle` terminal import accounting passed within the 219 engine
tests in root epoch `2591137d-2b97-4d1e-ab24-8ba8b43b494a`; see the
[root receipt](../agent-notes/2026-10-05-sess-omux-integrated-delivery.md).
Its separate persisted terminal aggregates cover source removal and
native import enrollment, not all lifecycle phases. Enrollment samples require
the same running job ID/generation to reach verified usable-grant completion or
a failed admitted terminal state; retries and stale completions add no sample.
Counts commit with the terminal outcome. Import durations cover only process-local
monotonic admission-to-terminal time before storage commit, including provider
work. Pre-admission queues, commit/reply time and local/provider wait splits are
absent; restart-lost duration remains unknown. Partial persisted counts do not
establish scheduled coverage or an achieved SLO/SLA.
Browser decoder refusals before stable operation authority have no honest unique
attempt denominator yet. Report missing ingress coverage; stable protocol attempt
identity and idempotent retry semantics are prerequisites for that accounting.
The bounded browser-attempt ledger narrows that accounting to the existing
production-disabled import capability refusal for a validated, authorized browser
context. Durable transaction fixture and engine gates passed in root epoch
`fa904145-6932-41f0-aa68-1672ea3a1b75`; this does not prove installed-browser or
live enrollment behavior. It uses exact-byte
same-ID replay without recounting and explicit unmeasured coverage on bounded
authority exhaustion. Inspect `browser_refusal_coverage` for
`recorder_unavailable`, `authority_capacity_exhausted` or partial authorized-context
coverage; timing remains unknown. Legacy connected sources lacking source
generation remain unmeasured until reconnect. This lane does not enable exports,
provide a browser baseline or establish an achieved SLO.
