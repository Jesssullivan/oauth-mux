# Native-reset ratification push evidence

This record covers the user-authorized focused push beginning
2026-10-02 23:41:49 America/New_York. Twelve GPT-6.1 Sol workers reviewed
disjoint product, acceptance, decisions, custody, native integration, reliability,
repository roles, subtraction, website, milestones and Linear scopes.
The root integrated authority and local drift checks. Source changes remain
uncommitted; no release, deployment, provider evaluation or service installation
is implied.

## Review results

The [current docs index](../README.md) connects the product charter, 22 user
journeys, support/completeness gates, eight ADRs, lifecycle/custody and native
adapter contracts, threat model, reliability objectives and repo roles.
[The retirement inventory](../history/retired-design-inventory.md) records 90
deleted obsolete documents, 27 unchanged historical references and three research
packets moved under history. Historical evidence, fixtures and stable release
claims retain their boundaries.

The reviews identified concrete implementation gates: Linux runtime-directory
placement; backup restore preserving tombstone/generation authority; native
request identity and mutation-outcome reconciliation; production refresh
adoption/revocation; actual vault/desktop/service execution; upstream native-hook
availability and exact-version live continuity; optional browser acquisition
schemas; and privacy-safe SLO instrumentation. These remain acceptance work,
not implemented capabilities. [The Linear receipt](../tracker-updates/native-ratification-2026-10-02.md)
records the actual tracker changes and dependencies.

`//:docs_check` checks classified current documents, repository links, acceptance
IDs, retired execution examples and four checkpoint deadlines/status coherence.
It excludes historical links from current operational validation. This guard
cannot prove implementation, actual uptime, installed usability or live handoff.

## Current local execution receipts

The predecessor implementation receipts are in
[the native-reset evidence](native-reset-evidence-2026-10-02.md). Changes in this
push primarily affect contracts, authority, tracker records, issue templates,
documentation checks and SPA copy; native runtime and upstream patch are unchanged.
New local runtime check receipts are recorded here after execution.

The current authority graph passed preliminary `//:docs_check` validation in
invocation `70147176-f8df-436f-bad1-64915be1b34e`. Its adversarial guard suite
passed 21 cases in invocation `d3ab92bd-123d-4dd6-8d22-9b6132e2e946` using
`nix develop --command bazelisk test //:docs_guard_test`.
The guard checks 22 user journeys and 107 total acceptance/decision identifiers;
the earlier worker summary's 21-journey count was corrected against declarations.

The final declared graph passed 39/39 project test targets, with 38 valid cached
results and one executed current-document check, in invocation
`2037eefc-b67f-4d3b-b44c-5d86d44cd707` (14.165 s):

```sh
nix develop --command bazelisk test //... --keep_going --jobs=4
```

All 68 build targets passed in invocation
`cb58e4c8-4bf8-4cb6-9862-cc8dfd4933d1` (10.387 s):

```sh
nix develop --command bazelisk build //... --jobs=4
```

Logs: `/tmp/omux-ratification-all.log` and
`/tmp/omux-ratification-build.log`. The documentation check classified 34 current
documents and 29 historical references, resolved 189 local links and checked 107
acceptance/decision IDs, four checkpoint records and 75 tracker mutation receipts.
After this graph receipt, only guard regression coverage, evidence prose and
checkpoint statuses were reconciled; the affected documentation targets are
validated again separately. Runtime/native/provider/platform support is unchanged.

Final affected-target validation passed `//:docs_check` and `//:docs_guard_test`
in invocation `db13fc19-33e7-4164-bc7b-4a8bef61f48e` (6.864 s):

```sh
nix develop --command bazelisk test //:docs_check //:docs_guard_test --test_output=errors
```

All 23 adversarial cases passed, including rejection of a well-formed invocation
ID absent from its referenced receipt. The documentation graph retains the
counts above. Both repository diffs pass `git diff --check`; the historical
evidence/fixture directories have no changes against the baseline.

The separate SPA passed all seven final declared gates after copy changes:
invocation `37d18662-9b09-4e1b-a9fd-2d140aa4734f`, zero skipped/failing, using
`nix develop --command bazelisk test //:check //:archive_check //:format_check //:playwright_chromium_smoke //:playwright_local_route_smoke`.
Its runtime-generated bundle remains SHA256
`f16dabca84e7dc14ea3bd1746cdb05d9de2a27703479c3936a2a2b8532a246af`.
The site is uncommitted and undeployed on `feature/native-account-custody-reference`.

## Milestone and promotion limits

The [weekend plan](../plans/omux-ratification-weekend-push-2026-10-02.md) and
[.goal ledger](../../.goal/omux-weekend-2026-10-02.json) record exact deadlines,
actual deliverables and remaining prerequisites. Local checks, tracker status,
ratified decisions and elapsed time cannot promote native support. Codex remains
an upstream hook candidate, browser provider exports remain disabled, Claude
request continuity remains unimplemented, and real vault/macOS/clean-install/live
provider gates remain unrun. SLO numbers are adopted measurement targets with
no current contractual SLA or staffed support agreement.

H3 contract ratification and H5 existing-project reconciliation passed before
their deadlines. H10 local acceptance readiness passed with the current local
graph and explicit resource/implementation next actions. The weekend milestone
remains unrun; its exact platform/native/provider acceptance is not replaced by
this completed ratification push. Each missing gate has a prerequisite, next
action and tracker owner role in the ledger and reconciled backlog.
