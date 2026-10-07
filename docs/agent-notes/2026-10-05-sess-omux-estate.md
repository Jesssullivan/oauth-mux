# Omux estate and delivery audit — 2026-10-05

Authority: user-authorized 15-hour implementation, superseded-tree reconciliation
and administrative delivery; repository `AGENTS.md`, R-N11/R-N12/R-N13 and
R-HOOK-CONVERGENCE-20261004. This is a read-only estate audit, not a merge receipt.

## Observed state

The only registered worktree is `/srv/fast-local/jess/git/oauth-mux`, on
`codex/omux-native-reset` at `f5f83c1ad99c2920de6759791b327a99a02a2ec5`.
Local `main` and cached `origin/main` have the same commit. Inspection observed
604 status entries, with mixed staged/unstaged modifications and new files.
Counts are snapshots during parallel implementation; they do not delimit an
approved commit. Do not reset, globally stage, stash or remove the working tree.

Live GitHub main is `134e4603b16c539316c1ea72194cae523cedab9f`, one commit ahead:
[PR #524](https://github.com/Jesssullivan/oauth-mux/pull/524), TIN-863 synthetic
MCP resource audience tests and metadata parsing, modifies only `src/probe.zig`.
That file is deleted in the reset's existing staged retirement. Reconciliation
must preserve #524 in Git history and explain its historical scope; it must not
restore the retired implementation into the new action graph.

Main protection currently enforces admins, requires an up-to-date branch and
eight legacy CI contexts: `test`, `nix`, and cross-compile for x86_64/aarch64
Linux musl, macOS and Windows. The reset removes automatic CI and defers Windows.
These protection requirements therefore conflict with the authorized execution
model. Do not assume `gh pr merge --admin` bypasses enforced administrator
protection. Any protection mutation needs an explicit reviewed configuration
and receipt; preserve unrelated safeguards. Local declared validation and exact
source receipts must be available before delivery.

## Existing PR disposition proposals

| PR | Existing scope | Proposed reset disposition |
|---|---|---|
| [#526](https://github.com/Jesssullivan/oauth-mux/pull/526) | Private GloriousFlywheel checkout retirement, ci-templates migration | Superseded by local declared Nix/Bazel execution and removal of automatic CI. Close with linked reset authority, preserving branch/commit history. Do not merge the retired CI topology. |
| [#525](https://github.com/Jesssullivan/oauth-mux/pull/525) | TIN-1803 legacy route-state schema and golden JSON | Review for reusable redaction predicates against new typed contracts. Close as superseded after identifying replacement paths; do not graft old runtime types. |
| [#523](https://github.com/Jesssullivan/oauth-mux/pull/523) | v0.2 readiness/no-FFI release gates | Superseded where zero-C/no-FFI constraints conflict with intentional SQLite/libcurl/native UI dependencies. Preserve historical v0.2 claims and reviewed evidence; do not merge old constraints. |

No PR was closed, merged or pushed during this audit.

## Branch and worktree cleanup boundary

No extra registered worktree exists to reap. Branch names starting `worktree-wf_`
are refs, not proof of existing disposable directories. The following local refs
are ancestors of the audited HEAD and may be proposed for ordinary `git branch
-d` after root review and a fresh ownership/worktree check:

- `checkpoint/neo-insurance-20260716`
- `codex/tin-1829-stage2-managed-boundary-20260812`
- `codex/tin-2052-request-lock-admission-20260812`
- `codex/tin-2723-linux-service-containment-20260731`
- `codex/tin-2799-v02-install-contract-20260731`
- `worktree-wf_8af60dde-5a8-1`
- `worktree-wf_9c60e333-0bb-1`
- `worktree-wf_c302d283-357-1`
- `worktree-wf_c866e7f9-7cf-1`
- `worktree-wf_e2a7ce64-22f-1`
- `worktree-wf_ee8f9fd7-341-1`

Keep active reset and `main`. All other local branches have commits not proven
reachable from audited HEAD. A gone remote tracking ref is not proof that its
local changes were merged. In particular archive/checkpoint refs and experimental
candidate sources/ELFs remain preserved; no forced branch deletion or recursive
filesystem cleanup is justified by this audit.

## Concrete delivery sequence

1. Finish concurrent changes, review explicit tracked/new/deleted path inventory,
   and retain the staged baseline separately from new implementation scope.
2. Produce locked Nix/Bazel validation receipts for the exact deliverable snapshot.
   A dirty-source receipt does not establish a committed or shipped artifact.
3. Prepare a reviewed reset commit using an explicit path list; include deliberate
   legacy retirement and new source inputs. Do not use blind `git add -A`.
4. Reconcile live main in an isolated integration checkout. Treat the #524 legacy
   `src/probe.zig` modify/delete conflict explicitly, preserving both parent
   histories without restoring the retired build graph.
5. Open/update the reset PR with architecture authority, exact commit, validation,
   remaining ordinary-launch/native-resume/handoff gates and installed coverage.
6. Review the exact branch-protection transition required by retired CI, preserve
   protections compatible with local evidence, and record administrative actions.
7. Merge only the reviewed exact PR head, read back main and record commit identity.
   Release, publication and provider access retain their own authorization.
8. Close superseded PRs with replacement-path links. Recheck ancestry and ownership
   before removing reviewed merged local refs; never delete an active checkout.

Candidate README audit outside `integrations/codex-upstream` found explicit
unshipped/limited-proof wording in owner/recovery artifact and runtime READMEs.
No vendor-supplied Omux hook dependency was found there. Historical evidence and
tracker snapshots still contain older stock-hook wording; preserve their original
receipts and supersede temporal interpretations in current authority instead.

## Scoped execution disk audit

Read-only inventory on October 5 observed `/home` at 95%, 7.7 GiB available.
`/srv/fast-local` reports 560 GiB at its mount root, but paths beneath owner
`/srv/fast-local/jess/{state,git,cache}` report only 19 GiB available and 99%.
The same XFS mount uses `prjquota`; the discrepancy is consistent with a project
quota, not a separate roomy owner scratch mount. These owner directories belong
to jess; state/git are mode 0700 and cache is 0755. Do not plan around 560 GiB.

Keep cache `bc988dbbbbc771e13245d8d338d52eed07f226e2f4dc71dcae1e46246cbbef88`
and its inventory producer epoch `d78336cf-c1ad-4b6a-b9f0-ac5797eef583`.
Keep dirty incident cache `22bae981906820d78115cd76f162a52f65527b5d7d9ff4be93c27824e4f4bf45`
and epoch `449725a2-fbfe-4553-808c-e51d86b1cf61`; repository Bazel symlinks
currently target that incident cache. Do not repair/adopt/delete either cache.

Conditional superseded candidate:
`/home/jess/.local/state/omux-execution-20261005/cache-0e1d597c9f6af9e4a84f84f7bb1f2c6dce3c6891a1a8d4f4e58bb3f5cb6894d1/output-base`.
Owner marker is clean and cites epoch `c5e34cd7-c72c-4f74-98bd-0cede3d329b5`;
the receipt SHA256 was verified as
`42a14efba13eab7dfa905585a5233bfadf5f0695d7e46bc2c6ccec66f734dfdd`.
Receipt exit is 1, with `descendants_empty: true`. Recorded supervisor PID
3319266 and observed former worker PIDs 3320106/3320452 are absent. Scoped
process inspection found no workload referencing this state root, only this
inspection. The cache has no evidence preservation receipt; its testlogs and
producer outputs require an independent bounded copy/hash inventory before
whole-output pruning. Smallest possible disposable scope is its
`output-base/sandbox/{sandbox_stash,_moved_trash_dir}` after confirming no unique
failed-action evidence is retained there and holding both execution/cache locks.

Older UUID output bases with verified empty descendants are additional
conditional candidates, while retaining their sibling receipts/logs:

| Epoch | Measured output-base bytes (du rounded) | Receipt outcome |
|---|---|---|
| `a620334d-f1df-45c4-8628-bcd5d1655eb0` | 1.1 GiB | exit 1, empty descendants |
| `5174fad1-e9d3-4e3e-95f8-74a27dbebe59` | 638 MiB | exit 1, empty descendants |
| `afcddb75-5a42-45ec-b9cd-cf0b3da7df32` | 330 MiB | exit 1, empty descendants |
| `50669f4e-fe7b-490e-89ce-190436d0653b` | 60 KiB | exit 32, empty descendants |
| `05d7c7e7-29c7-4c24-8099-eb56ac766025` | 1.3 GiB | exit 1, empty descendants |
| `80a8c353-0939-4158-9f73-8a8e926d08c9` | 150 MiB | exit 0, empty descendants |
| `bdbddca6-d527-419e-abdf-4ceef8db710a` | 759 MiB | exit 1, empty descendants |

The 79 MiB `e4ce4913` output base has unverified cleanup and is excluded.
Other epochs with `descendants_empty: false` remain excluded regardless of size.
For every proposed prune, preserve successful/failing XML/stdout, source and
generated artifacts, invocation/profile evidence and exact fixture dependencies
outside the target before deletion; no copied-evidence parity is assumed.
Acquire global/cache locks, recheck ownership/PID-start identity and unpopulated
unit cgroup, validate evidence hashes, then record exact path/prior receipt/
result. This audit deleted nothing. See
[cache retention policy](2026-10-05-owned-cache-retention-plan.md).

Inspection process receipt: `ship_estate | own du PID 1186838, exact command and
parent verified | slow recursive inode scan no longer needed for candidate
decision | R-N11 | active read-only inventory | TERM requested; no workload or
service signalled`. The partial scan does not establish total cache byte size.

## Source-only minimal prune helper

`tools/prune_epoch_runfiles.py` implements the safer minimal prune proposal.
Root owns final manual test target wiring for `//tools:prune_epoch_runfiles`.
Root schedules `//tools:prune_epoch_runfiles_test` before any operator execution;
source authorship alone proves nothing. No deletion was run.

The helper requires an exact operator JSON plan containing optional `current_epoch` and
up to eight `{uuid, receipt_sha256}` rows. It accepts only canonical UUID roots,
never cache names. Receipt bytes must match, descendants must be recorded empty,
recorded main/supervisor PIDs must be absent, and the exact recorded unit cgroup
must be retired or unpopulated. Existing/reused PIDs conservatively refuse.
The helper authenticates `OMUX_EXECUTION_GUARD`, exact private current supervisor
UUID/PID/start identity, its own current unit cgroup, and `/proc/locks` FLOCK WRITE
ownership of the exact `execution.lock` device/inode by that supervisor PID.
It additionally confirms the lock is busy and never releases the controller's
lock. Missing visibility refuses. A per-epoch `prune.lock` serializes maintenance.
State directories remain owned 0700 trusted directories. The public declared
plan may use a Bazel runfiles symlink, resolved once before bounded regular
nofollow/nonblock read with owned/no022/stable-byte verification.
`--plan-sha256` binds exact operator plan bytes. `--apply` is explicit; default
writes a dry-run audit. Admission is rechecked before each epoch.
Omitted `current_epoch` or literal `from_guard` derives the runtime current UUID
from authenticated guard context, allowing the old-target plan to be declared
before the new maintenance epoch exists.

Only directory/symlink names ending `.runfiles` within configuration `bin`
directories under `output-base/execroot/_main/bazel-out` can be deleted.
Regular bin artifacts, all testlogs, receipts, logs, profiles, external source,
action caches, sandbox content and original manifests remain in place.
Sandbox pruning is deliberately omitted because failed sandboxes can retain
unique diagnostics. This narrower helper may reclaim less than full-cache size.
No process is signalled and no cache is adopted.

Before the first removal it appends/fsyncs a per-epoch test-evidence hash manifest
and candidate inventory to `prune-audit.jsonl`. Each runfiles root has durable
intent and completion rows; member count summaries fsync every 256 removals
and at root completion, avoiding sync per file. Partial failures append an
explicit resumable result; a reserved 2 KiB terminal budget retains that receipt.
Retained testlogs remain the original evidence bytes. A resumed run generates a
fresh inventory and removes only remaining candidates, preserving prior rows.
Symlinks are unlinked without following; directory operations use nofollow
descriptor-relative traversal. Limits are one million visited members, 64 MiB test
evidence, 8 MiB audit, 256 candidate descriptors and 120 seconds per epoch. Root must ensure
the selected plan current epoch matches its actual guard epoch before invocation.

Declared regressions cover outside symlink preservation, regular binary/test
evidence retention, current/cache-shaped epoch refusal, unknown cleanup/live PID
refusal and finite traversal. All remain unrun at this source checkpoint.

Reviewed plan actually executed by root under epoch
`2591137d-2b97-4d1e-ab24-8ba8b43b494a`:
`tools/prune_epoch_plan.json` SHA256
`79349b598e1807093e4bbabe4c8eb7cc9bf6c0f506ce6740fcc856f108c27dd1`.
The original six-row proposal was narrowed to three admissible rows below.
`a620334d`, `5174fad1` and `afcddb75` were excluded: their original cleanup
receipts contain neither MainPID nor supervisor identity. Empty-descendants
flags alone did not authorize this helper to prune them. No deletion is claimed
for those excluded roots.

```json
[
  {"uuid":"05d7c7e7-29c7-4c24-8099-eb56ac766025","receipt_sha256":"db4a833f509b9e7ae8990a46439e8857a951c7f536990f7975cba49789e6079d"},
  {"uuid":"80a8c353-0939-4158-9f73-8a8e926d08c9","receipt_sha256":"63c6639628e34e8f5240e0960f2aaebc3c12f2f81504bab89def0bbfe5e258b7"},
  {"uuid":"bdbddca6-d527-419e-abdf-4ceef8db710a","receipt_sha256":"126be7b2838de6964a78ae8bdc2b6bcbc40957cd4633588fa39b570133d2f900"}
]
```

Readback confirms `//tools:prune_epoch_runfiles_apply` PASSED in 147.7 seconds
across the three bounded epochs. The encompassing mixed-target guard receipt
has exit 1, `descendants_empty: true`, no controller failure, and preserved
test evidence (16 files, 56,554 bytes, manifest SHA256
`46d1999868da81cc07d518f82bb4023eac6325ebb7ba8324a59f84e099665909`).
The prune pass does not convert the failed overall graph into a pass.
Guard receipt SHA256:
`23a1c5c5cce1f3cc93a6950f5b410600a929eeeb0092083f7728af1f09b6404a`.

| Original UUID prefix | Removed runfiles members | Hashed test-evidence files retained | Runfiles roots | Audit SHA256 |
|---|---:|---:|---:|---|
| `05d7c7e7` | 703,603 | 39 | 20 | `c4ef081c08f455e86c93d8a98016eb10899455a2f035b9cf20ad0f6c03dcc874` |
| `80a8c353` | 230,979 | 9 | 3 | `fc300f40ac3d16fbc23bedb46c6a3379d152596c5b419cfec7a0c8cb3ebf46f1` |
| `bdbddca6` | 386,078 | 18 | 7 | `43fc14dcb0e173223de649d52f95d367a02171e28ea02b9e91a97221bc470bed` |

Each original epoch's `prune-audit.jsonl` ends with `apply: true`,
`complete: true` and its listed count: 1,320,660 members total. Readback also
confirms earlier inspect manifests precede actual apply manifests. This agent
performed no additional deletion or cache mutation. `/home` readback remains
98% used, 4.2 GiB available; member removal counts do not establish reclaimed
byte totals or resolution of disk pressure. All cache producers/incidents remain
outside this plan.

## Reviewed supersession actions — 2026-10-05 14:03 UTC

Authority: explicit user instruction to retire superseded tickets/proposals and
reconcile architecture; repository AGENTS.md and R-N13. Root and the estate
reviewer independently re-read the current PR heads, diffs and comments. All
three proposals are open and unmerged, with heads matching the earlier review.
Only reversible closure and explanatory comments are selected; preserve branches,
commits, reviews, historical evidence and branch protection. No publication,
merge, credential/service mutation or replacement-proof promotion is implied.
The earlier proposed GitHub reset-document links above are not published
references; the exact selected messages below use Linear links and source paths.

### PR #523

Pre-action: https://github.com/Jesssullivan/oauth-mux/pull/523, `open`, merged=`false`,
head `2379beffab4f3076fa2aeb02ba157103d70509ec`, branch `jess/tranche3-omux-release-lane-hardening`,
base `134e4603b16c539316c1ea72194cae523cedab9f`. 8 changed paths.

Exact selected comment:

> Superseded by the user-ratified native account-lifecycle redesign, tracked under [TIN-2057](https://linear.app/tinyland/issue/TIN-2057), with installation/release work under [TIN-2063](https://linear.app/tinyland/issue/TIN-2063) and [TIN-2050](https://linear.app/tinyland/issue/TIN-2050).
>
> Automatic CI, Just/Zig release entrypoints, zero-C/no-FFI requirements and the old package projection conflict with the current design. This proposal is being closed without merging. Version-specific CHANGELOG coverage, advisory tag drift, manifest-derived membership and explicit membership-widening review remain release requirements; replacement check parity is not established by this closure.
>
> Current workspace authority is `docs/plans/omux-native-account-lifecycle-reset-2026-10-02.md` and `docs/plans/omux-integrated-delivery-sprint-2026-10-05.md`; predicate reconciliation is recorded in `docs/agent-notes/2026-10-05-sess-omux-estate.md`. Those reset changes are not yet published, so these are source paths rather than claims that remote documentation exists.
>
> Reviewed head: `2379beffab4f3076fa2aeb02ba157103d70509ec`. Branch, commits and historical release evidence are retained. The redesign remains experimental and unshipped; closure establishes no installed/native resume, live handoff, achieved SLO or SLA.

### PR #525

Pre-action: https://github.com/Jesssullivan/oauth-mux/pull/525, `open`, merged=`false`,
head `b2e4a01edd463ae198c48d73b0277518ff680139`, branch `jess/tin-1803-redacted-route-state-truth-for-v02-accounts-status-and`,
base `134e4603b16c539316c1ea72194cae523cedab9f`. 20 changed paths.

Exact selected comment:

> Superseded implementation for [TIN-1803](https://linear.app/tinyland/issue/TIN-1803) under the user-ratified native account-lifecycle redesign, coordinated in [TIN-2057](https://linear.app/tinyland/issue/TIN-2057).
>
> Retain the useful requirements: closed redacted public metadata, explicit unknown/stale provenance, justified reset windows, nonnegative lease counts, freshness deadlines and consistent status interpretation. The proposed nine-state total order was not ratified and does not become policy through this closure. The implementation depends on retired managed-launch runtime types and standalone Python/Just execution, so it is being closed without merging.
>
> Current workspace replacement authority is `src/domain.zig`, `src/control.zig` and `docs/spec/native-adapter-contract.md` (NAC-006/007/017); reviewed predicates are recorded in `docs/agent-notes/2026-10-05-sess-omux-estate.md`. These reset sources are not yet published. Replacement fixture parity and live status evidence remain open; closing this proposal does not complete TIN-1803.
>
> Reviewed head: `b2e4a01edd463ae198c48d73b0277518ff680139`. Branch, commits and historical fixture evidence are retained. No native support, continuity or release claim is promoted.

### PR #526

Pre-action: https://github.com/Jesssullivan/oauth-mux/pull/526, `open`, merged=`false`,
head `612a393e068cf45d522e68cf4f0a223f5fdb4598`, branch `jess/r331-ci-templates-enrollment`,
base `134e4603b16c539316c1ea72194cae523cedab9f`. 7 changed paths.

Exact selected comment:

> Superseded by the user-ratified local declared execution design, coordinated under [TIN-2057](https://linear.app/tinyland/issue/TIN-2057) and [TIN-2063](https://linear.app/tinyland/issue/TIN-2063).
>
> The current redesign removes automatic CI and the private GloriousFlywheel checkout dependency. It does not migrate those jobs to another runner. Build/test/check execution uses the locked Nix/Bazel action graph; provenance remains truthful and version-bound. The earlier GF review remains valid historical evidence for its reviewed R331 scope, but its conditional merge recommendation does not govern the new topology.
>
> Current workspace authority is `AGENTS.md`, `docs/decisions/007-local-declared-execution.md` and `docs/plans/omux-integrated-delivery-sprint-2026-10-05.md`; these reset changes are not yet published. Reviewed head: `612a393e068cf45d522e68cf4f0a223f5fdb4598`.
>
> Closing this proposal without merging preserves its branch, commits and historical review. Branch-protection transition and operator-owned App/credential retirement, OIDC/cache and deploy-key decisions remain separate, unverified work. This action changes no protection, credentials, services or GF ownership and establishes no product acceptance.

Closure readbacks at 14:04 UTC confirmed all three PRs closed and unmerged,
with exact original heads, branches and descriptions retained:

- #523: [comment 5996065865](https://github.com/Jesssullivan/oauth-mux/pull/523#issuecomment-5996065865), closed 14:03:24 UTC.
- #525: [comment 5996071563](https://github.com/Jesssullivan/oauth-mux/pull/525#issuecomment-5996071563), closed 14:03:43 UTC.
- #526: [comment 5996077252](https://github.com/Jesssullivan/oauth-mux/pull/526#issuecomment-5996077252), closed 14:04:02 UTC; original GF-seat comment retained.

Exact before bodies, selected comment bodies and relevant readbacks are in
`superseded_pr_closures_1404` of the existing tracker JSON. No branch deletion,
merge, protection, credential, service or live acceptance action occurred.


## Exact PR review and proposed close messages

Live PR heads are not the local branch heads: #523 `2379beffab4f3076fa2aeb02ba157103d70509ec`,
#525 `b2e4a01edd463ae198c48d73b0277518ff680139`, #526
`612a393e068cf45d522e68cf4f0a223f5fdb4598`. Review uses GitHub PR files/diffs.

#523 changes eight paths: `.github/workflows/ci.yml`, `docs/release-runbook.md`,
`docs/v02-package-lane-migration-plan.md`, `scripts/check-changelog-entry.sh`,
`scripts/no-ffi-surface-guard.sh`, `scripts/release-local.sh`,
`scripts/tag-drift-check.sh`, `test/test_release_manifest_v02_consumer_schema.py`.
Preserve the intent of version-specific CHANGELOG coverage before release,
advisory commit/date drift, manifest-derived membership and explicit review of
membership widening. These remain release follow-ups unless exact replacement
checks prove them; current delivery tests are not asserted as equivalents.
Reject no-C/FFI and fixed two-binary/Windows package assumptions for the reset.

Proposed #523 close body:

> Superseded by the experimental native account-lifecycle reset:
> [architecture](https://github.com/Jesssullivan/oauth-mux/blob/codex/omux-native-reset/docs/plans/omux-native-account-lifecycle-reset-2026-10-02.md),
> [delivery implementation](https://github.com/Jesssullivan/oauth-mux/blob/codex/omux-native-reset/delivery/README.md),
> [estate reconciliation](https://github.com/Jesssullivan/oauth-mux/blob/codex/omux-native-reset/docs/agent-notes/2026-10-05-sess-omux-estate.md).
> Automatic CI, Just/Zig release entrypoints, zero-C/no-FFI requirements and the
> old package projection conflict with the active reset and will not be merged.
> Version-specific CHANGELOG release coverage, advisory tag drift and explicit
> artifact membership review remain retained release predicates; closing this
> legacy implementation does not mark those replacements complete. Historical
> release evidence is preserved. The reset remains unshipped and does not prove
> ordinary Codex launch/resume or same-process provider handoff.

#525 changes twenty paths: one design document, one schema, one Python validator,
one Python golden test and sixteen fixture files. Useful predicates are closed
public field sets/no raw identifiers, state/provenance consistency, reset metadata
only on window-bound states, nonnegative lease counts, freshness deadlines and
common status interpretation. The proposed nine-state total order is expressly
unratified and must not become policy through retirement. Current contracts
`NAC-006`, `NAC-007`, `NAC-017` and `src/control.zig`/`src/domain.zig` are replacement
authorities; this audit does not prove all old fixture predicates implemented.

Proposed #525 close body:

> Superseded implementation for TIN-1803 under the experimental native reset.
> Current typed/runtime authority is
> [src/domain.zig](https://github.com/Jesssullivan/oauth-mux/blob/codex/omux-native-reset/src/domain.zig),
> [src/control.zig](https://github.com/Jesssullivan/oauth-mux/blob/codex/omux-native-reset/src/control.zig)
> and [native contract NAC-006/007/017](https://github.com/Jesssullivan/oauth-mux/blob/codex/omux-native-reset/docs/spec/native-adapter-contract.md).
> Retain closed redacted metadata, explicit unknown/stale provenance, justified
> reset windows, nonnegative leases and consistent status interpretation as
> requirements. The old schema depends on retired managed-launch types and
> standalone Python/Just execution, so it will not be merged. Its proposed total
> order was never ratified. Replacement fixture parity and live status evidence
> remain separate work; closing this PR does not complete TIN-1803 or promote
> native continuity. Exact reviewed predicates are recorded in the estate note.

#526 changes seven paths: `.github/actionlint.yaml`, the deleted private checkout
action, `ci.yml`, `release-proof.yml`, `remote-validate.yml`, `scripts/check-local.sh`
and deleted private-checkout smoke script. Retain absence of private checkout
dependency and prohibition on falsifying provenance. Cached remote execution,
runner targeting and context preservation are superseded, not portable predicates.

Proposed #526 close body:

> Superseded by [decision 007](https://github.com/Jesssullivan/oauth-mux/blob/codex/omux-native-reset/docs/decisions/007-local-declared-execution.md)
> and [repository execution authority](https://github.com/Jesssullivan/oauth-mux/blob/codex/omux-native-reset/AGENTS.md).
> The reset removes automatic CI and private GloriousFlywheel checkout rather
> than migrating those jobs to another runner. All build/test/check execution
> uses the locked Nix/Bazel graph. Provenance remains truthful and version-bound;
> old GF assertions do not become evidence for the reset. This closes the legacy
> CI topology proposal, not experimental product acceptance. Existing branch
> protection still requires a separately reviewed transition from retired CI
> contexts; no protection change is implied by this closure.

## Fresh cleanup review

Fresh inspection still finds one worktree and the same ancestor refs. Searching
current Markdown records found no dependency on the eleven exact ref names beyond
this note, but `checkpoint/neo-insurance-20260716` remains an explicitly named
insurance checkpoint and is excluded from deletion without affirmative review.
Its duplicate ancestor `worktree-wf_c866e7f9-7cf-1` is also excluded conservatively.
The remaining nine refs above are the concrete deletion proposal. Ancestry does
not establish cross-session ownership; root must resolve active-session ownership
before any removal. Delete only with ordinary `git branch -d`, never forced
deletion, and record prior commit identities in the receipt. No refs removed.

## Commit inventory snapshot

The following manifests are read-only Git inventory output, not staging consent.
Mixed entries intentionally appear in more than one list. New concurrent edits
after this snapshot require a new comparison before staging. The index baseline
has 224 changed paths; the working tree has 258 tracked changes; 213 paths are
untracked at this observation. Existing index entries must not silently replace
newer working bytes. Root reviews retirement, reset implementation, documentation
and pending candidate/source inputs before choosing an explicit commit path list.


### Staged baseline path/status manifest

```text
A	.gitattributes
D	.github/actions/checkout-gloriousflywheel/action.yml
D	.github/workflows/ci.yml
D	.github/workflows/live-provider-qa.yml
D	.github/workflows/npm-deprecate.yml
D	.github/workflows/public-source.yml
D	.github/workflows/registry-dry-run.yml
D	.github/workflows/release-proof.yml
D	.github/workflows/release.yml
D	.github/workflows/remote-validate.yml
D	.github/workflows/system-package-install-qa.yml
M	.gitignore
A	MODULE.bazel.lock
D	build.v02-exact-rebuild.zig
D	build.zig
D	build.zig.zon
D	dist/codex-shim.sh
D	dist/homebrew/oauth-mux.rb
D	dist/install.sh
D	dist/launchd/dev.xoxd.omux.keepalive.plist.tmpl
D	dist/systemd/oauth-mux-keepalive.service.tmpl
D	examples/claude.config.json
D	examples/codex-max.config.json
D	examples/figma-pat.config.json
D	examples/figma-plan.config.json
D	examples/figma.config.json
D	examples/flakehub.config.json
D	examples/github.config.json
D	examples/linear-api-key.config.json
D	examples/linear.config.json
D	examples/mcp-http.config.json
D	examples/vercel.config.json
D	justfile
D	release-manifest.json
D	schemas/managed-harness-jsonrpc-v2.schema.json
D	scripts/bazel/zig-build-action.sh
D	scripts/capture-claude-quota-headers.sh
D	scripts/capture-codex-wire.sh
D	scripts/check-authority-drift.sh
D	scripts/check-local.sh
D	scripts/check-managed-harness-instances.sh
D	scripts/check-retired-npm.sh
D	scripts/check-v0.1.15-characterization.sh
D	scripts/check-zig-test-root.sh
D	scripts/claude-isolated-browser.sh
D	scripts/claude-open-shim/open
D	scripts/codex-canonical-auth-canary.sh
D	scripts/codex-max-canary.sh
D	scripts/codex-wire-addon.py
D	scripts/dispatch-zig-reapi-proof.sh
D	scripts/dogfood-process-snapshot.py
D	scripts/e2e-local.sh
D	scripts/endpoint-free-check.sh
D	scripts/first-run-e2e.sh
D	scripts/github-tracker-comment.sh
D	scripts/gloriousflywheel-bazel.sh
D	scripts/homebrew-install-qa.sh
D	scripts/homebrew-version-check.sh
D	scripts/install-local-dogfood.sh
D	scripts/keepalive-service.sh
D	scripts/live-codex-mux-e2e.sh
D	scripts/live-provider-qa.sh
D	scripts/monitor-codex-status.sh
D	scripts/npm-ci-deprecate.sh
D	scripts/onboard-codex-max.sh
D	scripts/owned_temp_runner.py
D	scripts/paid-cohort-soak-snapshot.sh
D	scripts/project-version.sh
D	scripts/public-source-check.sh
D	scripts/registry-dry-run.sh
D	scripts/release-handoff.sh
D	scripts/release-local.sh
D	scripts/release-manifest-current.sh
D	scripts/release-smoke.sh
D	scripts/remote-validate.sh
D	scripts/resolve-npm-token.sh
D	scripts/resolve-release-version.sh
D	scripts/review-codex-wire-capture.py
D	scripts/secrets-scan-dir.sh
D	scripts/smoke-bazel-remote-contract.sh
D	scripts/smoke-broker-claude.sh
D	scripts/smoke-broker.sh
D	scripts/smoke-codex-401-propagation.sh
D	scripts/smoke-codex-acceptance.sh
D	scripts/smoke-codex-all-exhausted.sh
D	scripts/smoke-codex-capture-review.sh
D	scripts/smoke-codex-cassette-all-exhausted.sh
D	scripts/smoke-codex-cassette-replay.sh
D	scripts/smoke-codex-child-refresh.sh
D	scripts/smoke-codex-cli-ux.sh
D	scripts/smoke-codex-concurrent-sessions.sh
D	scripts/smoke-codex-provider-degraded.sh
D	scripts/smoke-codex-refresh-exactly-once.sh
D	scripts/smoke-codex-status-summary.sh
D	scripts/smoke-codex-tier-insufficient.sh
D	scripts/smoke-dogfood-process-snapshot.sh
D	scripts/smoke-gf-checkout-auth-contract.sh
D	scripts/smoke-github-tracker-comment.sh
D	scripts/smoke-home-manager-lane.sh
D	scripts/smoke-keepalive-service-containment.sh
D	scripts/smoke-public-source-workflow.sh
D	scripts/smoke-release-manifest-current.sh
D	scripts/smoke-release-workflow-version-authority.sh
D	scripts/smoke-remote-validate-contract.sh
D	scripts/smoke-retired-npm-boundary.sh
D	scripts/smoke-trace.sh
D	scripts/smoke-v02-stage2-observation.sh
D	scripts/smoke-version-check-stale-path.sh
D	scripts/stay-afloat-wrapper-doc-smoke.sh
D	scripts/summarize-codex-status.py
D	scripts/system-package-install-qa.sh
D	scripts/test-cassette-upstream.py
D	scripts/test-executable-compat.sh
D	scripts/test-refresh-exactly-once.py
D	scripts/test-stub-codex.py
D	scripts/test-stub-upstream.py
D	scripts/uninstall-local-dogfood.sh
D	scripts/v02-benchmark-metrics-local.sh
D	scripts/v02-posix-install-contract-inner.sh.in
D	scripts/v02-posix-install-contract-local.sh
D	scripts/v02-prerelease-bundle.zig
D	scripts/v02-prerelease-readiness-local.sh
D	scripts/v02-proof-predicate-manifest-local.sh
D	scripts/v02-proof-provenance-local.sh
D	scripts/v02-stage2-observation-local.sh
D	scripts/v02_posix_candidate.py
D	scripts/validate-managed-harness-instance.py
D	scripts/verify-zig-reapi-proof.sh
D	src/adapters/claude/child_authority.zig
D	src/adapters/claude/fake_upstream.zig
D	src/adapters/claude/main.zig
D	src/adapters/claude/session_capability.zig
D	src/adapters/claude/stage2_observer.zig
D	src/adapters/claude/verb.zig
D	src/adapters/claude/wire_proxy.zig
D	src/adapters/codex/app_server_client.zig
D	src/adapters/codex/main.zig
D	src/adapters/codex/wire_proxy.zig
D	src/age.zig
D	src/broker/account_pool.zig
D	src/broker/attempt_policy.zig
D	src/broker/decision.zig
D	src/broker/identifiers.zig
D	src/broker/lease_owner.zig
D	src/broker/lease_runtime.zig
D	src/broker/lease_state.zig
D	src/broker/lease_store.zig
D	src/broker/methods.zig
D	src/broker/mod.zig
D	src/broker/model_demand.zig
D	src/broker/route_observation.zig
D	src/broker/server.zig
D	src/broker/session.zig
D	src/broker/types.zig
D	src/broker_loader.zig
D	src/cassettes/claude_oauth_cassette.zig
D	src/cassettes/claude_oauth_cassette_tests.zig
D	src/cli.zig
D	src/codex_resume_index.zig
D	src/config.zig
D	src/doctor_binaries.zig
D	src/enroll/browser_launch.zig
D	src/enroll/callback_server.zig
D	src/enroll/callback_server_tests.zig
D	src/enroll/claude_login.zig
D	src/enroll/claude_reauth.zig
D	src/enroll/claude_reauth_tests.zig
D	src/enroll/device_code.zig
D	src/enroll/flow_composition.zig
D	src/enroll/reauth.zig
D	src/enroll/tests.zig
D	src/enroll/web_ui.zig
D	src/enroll/web_ui_tests.zig
D	src/env.zig
D	src/fixture_redaction.zig
D	src/health.zig
D	src/identity/claude_identity.zig
D	src/identity/claude_identity_source.zig
D	src/identity/claude_identity_tests.zig
D	src/identity/identity_graph.zig
D	src/identity/identity_graph_tests.zig
D	src/identity/identity_lane_integration_tests.zig
D	src/identity_hash.zig
D	src/keepalive/notify_adapter.zig
D	src/keepalive/refresh_race_tests.zig
D	src/keepalive/ui_server.zig
D	src/keepalive/ui_server_tests.zig
D	src/keepalive/warm_binding.zig
D	src/keepalive/warm_binding_tests.zig
D	src/keepalive/warm_runner.zig
D	src/keepalive/warm_runner_tests.zig
D	src/keepalive/warm_scheduler.zig
D	src/keepalive/warm_scheduler_tests.zig
D	src/lock_wait.zig
D	src/log.zig
D	src/managed_harness_contract.zig
D	src/notify.zig
D	src/oauth.zig
D	src/os_account.zig
D	src/pipeline.zig
D	src/probe.zig
D	src/product_identity.zig
D	src/provider.zig
D	src/provider_schema.zig
D	src/quota/advise.zig
D	src/quota/advise_tests.zig
D	src/quota/advisory_usage.zig
D	src/quota/bucket.zig
D	src/quota/bucket_tests.zig
D	src/reauth/orchestrator.zig
D	src/release_manifest.zig
D	src/release_manifest_gate.zig
D	src/repair_state.zig
D	src/runtime.zig
D	src/secret.zig
D	src/shell.zig
D	src/stage2_observer_module.zig
D	src/tests.zig
D	src/trace.zig
D	src/types.zig
D	src/version_check.zig
D	test/release_manifest_readiness_root.zig
D	test/stage2_observer_root.zig
D	test/test_v02_posix_candidate.py
```


### Tracked working-tree path/status manifest

```text
M	.bazelignore
M	.bazelrc
A	.bazelversion
M	.envrc
M	.github/ISSUE_TEMPLATE/bug_report.md
M	.github/ISSUE_TEMPLATE/config.yml
M	.github/ISSUE_TEMPLATE/live_handoff_evidence.md
M	.github/ISSUE_TEMPLATE/provider_request.md
D	.github/actionlint.yaml
M	.gitignore
A	.goal/omux-weekend-2026-10-02.json
M	AGENTS.md
M	BUILD.bazel
M	CHANGELOG.md
M	MODULE.bazel
M	MODULE.bazel.lock
M	README.md
A	clients/README.md
A	clients/linux/BUILD.bazel
A	clients/linux/main.cpp
A	clients/linux/omux-control.desktop
A	clients/linux/omux.service
A	clients/linux/omux_client.cpp
A	clients/linux/omux_client.h
A	clients/linux/transport_test.cpp
A	clients/linux/tray.cpp
A	clients/linux/tray.h
A	clients/macos/BUILD.bazel
A	clients/macos/ControlWindow.swift
A	clients/macos/DaemonConnection.swift
A	clients/macos/DaemonStore.swift
A	clients/macos/Info.plist
A	clients/macos/JSONValue.swift
A	clients/macos/OmuxApp.swift
A	clients/macos/ai.xoxd.omux.daemon.plist
A	delivery/BUILD.bazel
A	delivery/README.md
A	delivery/install.py
A	delivery/pack.py
A	delivery/portable.py
A	delivery/rules.bzl
A	delivery/runtime_audit.py
A	delivery/services/dev.xoxd.omux.plist.in
A	delivery/services/omux.service.in
A	delivery/test_cli.py
A	delivery/test_delivery.py
A	delivery/test_portable.py
A	delivery/test_relocation.py
M	docs/README.md
D	docs/adoption.md
M	docs/authority-map.md
A	docs/authority.json
D	docs/daemon-boundary.md
A	docs/decisions/001-native-application-continuity.md
A	docs/decisions/002-local-compatible-account-federation.md
A	docs/decisions/003-typed-lifecycle-and-capacity.md
A	docs/decisions/004-browser-source-conduit.md
A	docs/decisions/005-custody-and-runtime.md
A	docs/decisions/006-thin-native-clients.md
A	docs/decisions/007-local-declared-execution.md
A	docs/decisions/008-generated-spa-authority.md
A	docs/decisions/README.md
D	docs/dogfood-process-fanout.md
A	docs/governance/repository-roles.md
A	docs/history/README.md
R100	docs/research/omux-foundation-2026-07-02T0532Z.md	docs/history/research/omux-foundation-2026-07-02T0532Z.md
R100	docs/research/omux-orientation-gapmap-2026-07-02.md	docs/history/research/omux-orientation-gapmap-2026-07-02.md
R100	docs/research/omux-prompts-corpus-synthesis-2026-07-02.md	docs/history/research/omux-prompts-corpus-synthesis-2026-07-02.md
A	docs/history/retired-design-inventory.md
D	docs/home-manager.md
A	docs/implementation/native-reset-evidence-2026-10-02.md
A	docs/implementation/ratification-push-evidence-2026-10-02.md
D	docs/install-beta-matrix.md
D	docs/keepalive-service-units.md
D	docs/lifecycle.md
D	docs/live-provider-qa.md
D	docs/onboarding.md
A	docs/plans/omux-native-account-lifecycle-reset-2026-10-02.md
A	docs/plans/omux-ratification-weekend-push-2026-10-02.md
D	docs/policy/tos-posture-2026-05-05.md
A	docs/product/charter.md
A	docs/product/support-and-completeness.md
A	docs/product/user-stories.md
D	docs/productionization-ledger.md
D	docs/provider-repair-contracts.md
D	docs/qa-handoff-matrix.md
D	docs/reference/codex-0.135-auth-internals.md
D	docs/reference/oauth-mux-algorithms-and-complexity.md
D	docs/reference/tinyland-repo-manifest-notes.md
D	docs/registry-dry-runs-and-rollback.md
D	docs/release-install-lanes.md
A	docs/reliability/service-objectives.md
D	docs/runbooks/claude-5-account-keepalive-dogfood-2026-07-03.md
A	docs/runbooks/native-operations.md
A	docs/runbooks/omux-apple-toolchain.md
D	docs/runbooks/reauth-accounts-2026-06-01.md
D	docs/runbooks/statusline-advice-consumer-2026-07-09.md
A	docs/security/native-account-threat-model.md
D	docs/spec/account-enrollment-agent-contract-2026-05-01.md
D	docs/spec/architecture-review-2026-04-25.md
D	docs/spec/auth-state-models-and-adapter-extensibility-2026-06-12.md
D	docs/spec/background-stay-afloat-daemon-contract-2026-05-02.md
D	docs/spec/broker-worktree-quarry-todo-2026-05-05.md
D	docs/spec/claude-managed-hotswap-experiment-2026-07-14.md
D	docs/spec/codex-direct-http-probe-decision-2026-04-26.md
D	docs/spec/codex-inplace-auth-broker-proof-2026-05-02.md
D	docs/spec/codex-live-acceptance-checklist-2026-05-08.md
D	docs/spec/codex-managed-resume-ux-refactor-2026-05-06.md
D	docs/spec/codex-max-operator-plan-2026-04-25.md
D	docs/spec/codex-productionization-todo-2026-05-09.md
D	docs/spec/codex-session-store-portability-policy-2026-05-18.md
D	docs/spec/codex-upstream-usage-limit-handoff-proposal-2026-05-18.md
D	docs/spec/development-timeline-2026-04-27.md
D	docs/spec/dogfood-e2e-oauth-flow-plan-2026-04-30.md
D	docs/spec/dual-writer-refresh-designation-2026-06-13.md
D	docs/spec/future-adapter-roadmap-2026-05-10.md
D	docs/spec/gloriousflywheel-substrate-integration-2026-04-26.md
D	docs/spec/harness-adapter-pattern-2026-05-03.md
D	docs/spec/harness-session-authority-bridge-2026-05-05.md
D	docs/spec/homebrew-public-lane-decision-2026-05-01.md
D	docs/spec/in-agent-reauth-handoff-contract-2026-05-14.md
D	docs/spec/managed-harness-jsonrpc-v2.md
A	docs/spec/native-adapter-contract.md
A	docs/spec/native-lifecycle-and-custody.md
D	docs/spec/notification-delivery-survey-2026-07-09.md
D	docs/spec/oauth-mux-formal-model.md
D	docs/spec/oauth-mux-operational-hardening-plan-2026-05-20.md
D	docs/spec/oauth-mux-this-week-sprint-2026-05-26.md
D	docs/spec/oauth-mux-zig-reapi-target-class-plan-2026-06-14.md
D	docs/spec/observed-child-diagnostic-contract-2026-05-02.md
D	docs/spec/paid-cohort-soak-claim-policy-2026-05-03.md
D	docs/spec/paid-multi-account-proof-cohort-2026-05-01.md
D	docs/spec/product-adoption-sprint-2026-04-28.md
D	docs/spec/product-gap-issue-map-2026-05-01.md
D	docs/spec/production-publication-sprint-2026-04-28.md
D	docs/spec/provider-authoring-checklist-2026-04-26.md
D	docs/spec/provider-probe-admission-matrix-2026-04-26.md
D	docs/spec/provider-truth-matrix-2026-07-02.md
D	docs/spec/reauth-orchestrator-designation-2026-06-12.md
D	docs/spec/refresh-authority-adr-trace-2026-06-13.md
D	docs/spec/repository-ownership-and-url-2026-04-28.md
D	docs/spec/stay-afloat-permission-broker-contract-2026-05-01.md
D	docs/spec/stay-afloat-runtime-daemon-plan-2026-04-30.md
D	docs/spec/stay-afloat-supervisor-contract-2026-05-01.md
D	docs/spec/supervised-harness-restart-contract-2026-05-02.md
D	docs/spec/test-and-coverage-review-2026-05-05.md
D	docs/stay-afloat-wrappers.md
D	docs/tracing.md
D	docs/tracker-hygiene.md
D	docs/tracker-updates/2026-05-08/README.md
D	docs/tracker-updates/2026-05-08/issue-131.md
D	docs/tracker-updates/2026-05-08/issue-177.md
D	docs/tracker-updates/2026-05-08/issue-191.md
D	docs/tracker-updates/2026-05-08/issue-205.md
D	docs/tracker-updates/2026-05-09/README.md
D	docs/tracker-updates/2026-05-09/codex-auth-identity-and-oauth-flow-update.md
D	docs/tracker-updates/2026-05-09/codex-config-overlay-issue.md
D	docs/tracker-updates/2026-05-10/README.md
D	docs/tracker-updates/2026-05-20/README.md
D	docs/tracker-updates/2026-05-26/README.md
D	docs/tracker-updates/2026-07-09/gh-176-reconcile.md
D	docs/tracker-updates/2026-07-09/gh-445-valet-ladder.md
D	docs/tracker-updates/2026-07-09/tin-1830-close.md
D	docs/tracker-updates/2026-07-09/tin-2040-m3-park.md
D	docs/tracker-updates/2026-07-09/tin-2057-optin.md
D	docs/tracker-updates/2026-07-09/tin-2077-e1-claim.md
D	docs/tracker-updates/2026-07-09/tin-2400-e2-pullforward.md
D	docs/tracker-updates/2026-07-16/tin-2057-state-sync.md
D	docs/tracker-updates/2026-07-17/tin-2057-state-sync.md
A	docs/tracker-updates/native-ratification-2026-10-02.json
A	docs/tracker-updates/native-ratification-2026-10-02.md
A	extensions/BUILD.bazel
A	extensions/README.md
A	extensions/chromium/manifest.json
A	extensions/firefox/manifest.json
A	extensions/native_host_setup.py
A	extensions/native_host_setup_test.py
A	extensions/shared/acquisition.mjs
A	extensions/shared/adapters.mjs
A	extensions/shared/background.mjs
A	extensions/shared/bridge.test.mjs
A	extensions/shared/native.mjs
A	extensions/shared/popup.css
A	extensions/shared/popup.html
A	extensions/shared/popup.mjs
A	extensions/shared/protocol.mjs
A	extensions/shared/service.mjs
M	flake.lock
M	flake.nix
A	integrations/codex-upstream/BUILD.bazel
A	integrations/codex-upstream/README.md
A	integrations/codex-upstream/apply_upstream.py
A	integrations/codex-upstream/binary-overlay.tar.gz
A	integrations/codex-upstream/codex-0.157-auth-broker.patch
A	integrations/codex-upstream/manifest.json
A	integrations/codex-upstream/patch_io.py
A	integrations/codex-upstream/patch_test.py
A	integrations/codex-upstream/refresh_artifact.py
A	integrations/codex-upstream/upstream-base.tar.gz
A	integrations/codex-upstream/validation-overlay.patch
A	integrations/codex-upstream/validation.json
A	src/browser_bridge.zig
A	src/browser_grant.zig
A	src/catalog.zig
A	src/control.zig
M	src/daemon.zig
A	src/discovery.zig
A	src/domain.zig
A	src/engine.zig
A	src/engine_acceptance.zig
A	src/envelope.zig
A	src/integrations/claude.zig
A	src/integrations/codex.zig
A	src/integrations/git.zig
A	src/integrations/native_probe.zig
A	src/integrations/setup.zig
M	src/main.zig
A	src/native_probe_tests.zig
A	src/observer.zig
M	src/paths.zig
A	src/platform/file_metadata.zig
A	src/platform/vault_bridge.c
A	src/platform/vault_bridge.h
A	src/platform/vault_bridge_test.c
A	src/product.zig
A	src/reference.zig
A	src/setup_tests.zig
A	src/storage.zig
A	src/tests.zig
A	src/tls_probe.zig
A	src/transport.zig
A	src/vault.zig
A	tools/BUILD.bazel
A	tools/apple_repository.bzl
A	tools/archive.py
A	tools/arocc.BUILD.bazel
A	tools/codex-upstream-custody.md
A	tools/codex_upstream_archives.json
A	tools/docs_check.py
A	tools/docs_check_test.py
A	tools/entropy_test.zig
A	tools/macho.py
A	tools/macho_test.py
A	tools/macos_bundle.py
A	tools/macos_bundle_test.py
A	tools/native.h
A	tools/native_tool_info.bzl
A	tools/nix-workers.md
A	tools/nix_cc_toolchain.bzl
A	tools/nix_repository.bzl
A	tools/rules.bzl
A	tools/rules_zig_017.patch
A	tools/runtime_zig.bzl
A	tools/swift_rules.bzl
A	tools/toolchain_test.zig
A	tools/translate-c.BUILD.bazel
A	tools/zig-index.json
A	tools/zig_tools.bzl
```


### Untracked path manifest

```text
.goal/omux-integrated-delivery-2026-10-05.json
.goal/omux-native-admission-2026-10-04.json
.goal/omux-native-discovery-2026-10-04.json
.goal/omux-native-discovery-followon-2026-10-04.json
.goal/omux-native-evening-2026-10-03.json
.goal/omux-native-owner-2026-10-04.json
.goal/omux-native-safety-2026-10-03.json
clients/linux/runtime_paths.cpp
clients/linux/runtime_paths.h
clients/linux/setup_ui_test.cpp
clients/macos/RuntimePaths.swift
delivery/chromium_transport.mjs
delivery/dev_stage.py
delivery/extension_metadata.py
delivery/metadata_rules.bzl
delivery/test_dev_stage.py
delivery/test_extension_metadata.py
delivery/test_installed_browser.py
delivery/test_installed_chromium.py
delivery/test_installed_custody.py
delivery/test_installed_git.py
delivery/test_installed_native_discovery.py
delivery/test_installed_native_interop.py
delivery/test_installed_native_tui.py
docs/agent-notes/2026-10-04-sess-native-runtime-retirement.md
docs/agent-notes/2026-10-04-sess-omux-admission-sprint.md
docs/agent-notes/2026-10-04-sess-omux-codex-custody.md
docs/agent-notes/2026-10-04-sess-omux-evening-checkpoint.md
docs/agent-notes/2026-10-04-sess-omux-evening-graph.md
docs/agent-notes/2026-10-04-sess-omux-evening-linear.md
docs/agent-notes/2026-10-04-sess-omux-execution-incident.md
docs/agent-notes/2026-10-04-sess-omux-native-discovery.md
docs/agent-notes/2026-10-04-sess-omux-native-interop.md
docs/agent-notes/2026-10-04-sess-omux-native-owner-sprint.md
docs/agent-notes/2026-10-04-sess-omux-owner-authority.md
docs/agent-notes/2026-10-04-sess-omux-owner-codex-core.md
docs/agent-notes/2026-10-04-sess-omux-owner-codex-protocol.md
docs/agent-notes/2026-10-04-sess-omux-owner-graph.md
docs/agent-notes/2026-10-04-sess-omux-owner-install.md
docs/agent-notes/2026-10-04-sess-omux-owner-journey.md
docs/agent-notes/2026-10-04-sess-omux-owner-lifecycle.md
docs/agent-notes/2026-10-04-sess-omux-owner-peer.md
docs/agent-notes/2026-10-04-sess-omux-owner-reliability.md
docs/agent-notes/2026-10-04-sess-omux-owner-security.md
docs/agent-notes/2026-10-04-sess-omux-owner-vault.md
docs/agent-notes/2026-10-05-cached-site-inventory.md
docs/agent-notes/2026-10-05-chromium-installed-transport-lane.md
docs/agent-notes/2026-10-05-integrated-delivery-linear.md
docs/agent-notes/2026-10-05-sess-omux-estate.md
docs/agent-notes/2026-10-05-sess-omux-integrated-delivery.md
docs/implementation/native-admission-evidence-2026-10-04.md
docs/implementation/native-evening-evidence-2026-10-03.md
docs/implementation/native-interop-evidence-2026-10-04.md
docs/implementation/native-owner-evidence-2026-10-04.md
docs/implementation/native-safety-evening-handoff-2026-10-03.md
docs/implementation/native-safety-evidence-2026-10-03.md
docs/plans/omux-dedicated-evaluation-matrix-2026-10-04.md
docs/plans/omux-integrated-delivery-sprint-2026-10-05.md
docs/plans/omux-native-admission-sprint-2026-10-04.md
docs/plans/omux-native-discovery-resume-sprint-2026-10-04.md
docs/plans/omux-native-evening-push-2026-10-03.md
docs/plans/omux-native-interop-continuation-2026-10-04.md
docs/plans/omux-native-owner-custody-next-stage-2026-10-04.md
docs/plans/omux-native-owner-sprint-2026-10-04.md
docs/plans/omux-native-safety-sprint-2026-10-03.md
docs/spec/darwin-native-peer-carrier-proposal-2026-10-04.md
docs/tracker-updates/integrated-delivery-2026-10-05.json
docs/tracker-updates/integrated-delivery-2026-10-05.md
docs/tracker-updates/native-admission-sprint-2026-10-04.json
docs/tracker-updates/native-admission-sprint-2026-10-04.md
docs/tracker-updates/native-discovery-incident-2026-10-05.json
docs/tracker-updates/native-discovery-sprint-2026-10-04.json
docs/tracker-updates/native-discovery-sprint-2026-10-04.md
docs/tracker-updates/native-evening-push-2026-10-03.json
docs/tracker-updates/native-evening-push-2026-10-03.md
docs/tracker-updates/native-interop-results-2026-10-04.json
docs/tracker-updates/native-interop-results-2026-10-04.md
docs/tracker-updates/native-interop-resume-2026-10-04.json
docs/tracker-updates/native-interop-resume-2026-10-04.md
docs/tracker-updates/native-owner-sprint-2026-10-04.json
docs/tracker-updates/native-owner-sprint-2026-10-04.md
docs/tracker-updates/native-safety-sprint-2026-10-03.json
docs/tracker-updates/native-safety-sprint-2026-10-03.md
extensions/channel.py
extensions/channel_rules.bzl
extensions/channel_test.py
extensions/chromium/development.public-key
extensions/development_identity.py
extensions/shared/channel.mjs
extensions/shared/protocol.test.mjs
integrations/codex-adapter-delivery/BUILD.bazel
integrations/codex-adapter-delivery/README.md
integrations/codex-adapter-delivery/retirement-barrier-20261005.patch
integrations/codex-adapter-delivery/retirement_delta.py
integrations/codex-adapter-delivery/retirement_delta_test.py
integrations/codex-adapter-delivery/source-code-path-inventory-20261005.txt
integrations/codex-adapter-delivery/thread-manager-observed-diff-20261005.patch
integrations/codex-native-recovery-candidate/BUILD.bazel
integrations/codex-native-recovery-candidate/README.md
integrations/codex-native-recovery-runtime/BUILD.bazel
integrations/codex-native-recovery-runtime/README.md
integrations/codex-owner-candidate/BUILD.bazel
integrations/codex-owner-candidate/README.md
integrations/codex-owner-candidate/artifact_test.py
integrations/codex-owner-candidate/artifact_tooling_test.py
integrations/codex-owner-candidate/codex-0.157-auth-broker.patch
integrations/codex-owner-candidate/manifest.json
integrations/codex-owner-candidate/schema-import-receipt.json
integrations/codex-owner-candidate/validation-overlay.patch
integrations/codex-owner-candidate/validation.json
integrations/codex-owner-runtime/BUILD.bazel
integrations/codex-owner-runtime/README.md
integrations/codex-owner-runtime/codex-owner-runtime.tar.gz
integrations/codex-owner-runtime/runtime-manifest.json
integrations/codex-owner-runtime/runtime-receipt.json
integrations/codex-owner-runtime/runtime_inputs.bzl
integrations/codex-owner-runtime/runtime_package.py
integrations/codex-owner-runtime/runtime_package_test.py
integrations/codex-upstream/export_pristine_subset.py
integrations/codex-upstream/export_pristine_subset_test.py
integrations/codex-upstream/import_schema_bundle.py
integrations/codex-upstream/import_schema_bundle_test.py
integrations/codex-upstream/restore_source.py
integrations/codex-upstream/restore_source_test.py
nix/README.md
nix/consume-bazel-artifact.nix
nix/evaluation-tests.nix
nix/evaluation_runner.py
nix/evaluation_runner_test.py
nix/home-manager.nix
nix/ownership-witness.nix
src/instance.zig
src/instance_tests.zig
src/integrations/native_inventory.zig
src/mutation_authority.zig
src/native_inventory_test.zig
src/native_owner.zig
src/native_owner_fixture.zig
src/native_owner_probe_tests.zig
src/native_owner_removal_tests.zig
src/native_owner_request_tests.zig
src/native_owner_setup_tests.zig
src/native_owner_storage_tests.zig
src/native_owner_tests.zig
src/native_owner_work.zig
src/native_peer_tests.zig
src/onboarding.zig
src/onboarding_tests.zig
src/platform/native_peer.c
src/platform/native_peer.h
src/platform/native_peer_test.c
src/platform/peer.zig
src/platform/vault_realproof.c
src/platform/vault_realproof.sh
src/platform/vault_realproof_macos.sh
src/recovery.zig
src/reliability.zig
src/reliability_commit.zig
src/reliability_lifecycle_tests.zig
src/request_authority.zig
src/safety_adversarial_test.zig
src/setup_collector.zig
src/setup_collector_tests.zig
src/setup_evidence.zig
src/setup_evidence_tests.zig
src/snapshot_adapter_tests.zig
src/snapshot_admission.zig
src/snapshot_forget_tests.zig
src/snapshot_import_tests.zig
src/snapshot_migration_tests.zig
src/snapshot_native_tests.zig
src/snapshot_repair_tests.zig
src/snapshot_restart_tests.zig
tools/cached_nix_inventory.py
tools/cached_nix_inventory_test.py
tools/cc_toolchain_environment_check.bzl
tools/deployed_fixture.py
tools/deployed_fixture_test.py
tools/execution_guard.py
tools/execution_guard_probe.py
tools/execution_guard_probe_test.py
tools/execution_guard_test.py
tools/guard_cache.py
tools/guard_cache_test.py
tools/host-proof-custody.md
tools/host_cancel.py
tools/host_cancel_test.py
tools/host_cleanup.py
tools/host_cleanup_test.py
tools/host_closure.py
tools/host_closure_transfer.py
tools/host_closure_transfer_test.py
tools/host_graph.py
tools/host_graph_test.py
tools/host_probe.py
tools/host_recipe_probe.py
tools/host_route_probe.py
tools/host_route_probe_test.py
tools/host_tools_repository.bzl
tools/host_workspace.py
tools/host_workspace_test.py
tools/nix_evaluation_source.bzl
tools/nix_file_inventory.py
tools/nix_file_inventory_test.py
tools/nix_source_probe.py
tools/reapi_provenance.py
tools/reapi_provenance_test.py
tools/site_inputs_repository.bzl
tools/ssh_policy.py
tools/ssh_policy_test.py
tools/system_mask_policy.py
tools/system_mask_policy_test.py
tools/vault_proof_runner.py
```
