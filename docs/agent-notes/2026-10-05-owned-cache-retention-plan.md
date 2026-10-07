# Owned Bazel cache retention proposal

## Source follow-on: stable policy v2 and copier correction

Root reported epoch `449725` completed with workload status 1, guard status 125,
empty descendants, and preservation-incomplete: 28 files/73,244 bytes were copied,
but regular Bazel status files were treated as configuration directories. The
copier now selects only nofollow-stat-confirmed directories; a pure regression
includes both regular status files. The old receipt and dirty `22bae` key are
preserved, never adopted or repaired by this change.

Opt-in reuse now enters a fresh `cache-v2-<key>` namespace with marker schema 2.
The stable key binds canonical repository, UID/GID, manager, effective resource,
isolation and test-strategy profile, immutable tools/closures and policy version.
Graph and selected site-input bytes remain per-run receipt data and watched
Bazel inputs. Batch mode, locks, dirty fencing, verified cleanup, evidence copies
and uncached selected test execution remain mandatory. Legacy namespaces remain
historical; no pruning occurs. These source changes require root/security review
before execution and do not retroactively pass any epoch.

Authority: the user-authorized Omux implementation goal; AGENTS.md and
R-HOOK-CONVERGENCE-20261004, R-N11/R-N13. This is source inspection and a
proposed cleanup contract, not an executed prune or a containment proof.
The selected `d783` epoch was active during initial review. Root subsequently
reported exit 1 with empty descendants before authorizing source integration.

## Findings

`tools/execution_guard.py` preserves each UUID epoch's workload log and receipt.
`tools/guard_cache.py` preserves a receipt-bound cleanup fence and serializes
reuse. Current guard source does not declare per-epoch BEP output or copy the
successful tests' stdout/XML out of the reusable output base. Repeated tests may
overwrite that test evidence even without pruning. Copying only `workload.log`
is insufficient when successful output is suppressed by `--test_output=errors`.

## Proposed bounded prune

After the final graph is stable, preserve the current key, the two most recent
completed keys and explicitly pinned artifact-producer keys. Byte estimates and
age are advisory selection inputs; they never override ownership or proof checks.

Before pruning, archive the exact selected tests' logs/XML and BEP into their
UUID evidence directory using bounded nofollow copies and a digest inventory.
Bind selected package/runtime outputs to durable artifact locations before
releasing their producer key. Preserve every UUID directory, receipt, probe,
supervisor record and log. Never delete a referenced proof's only evidence.

A declared cleanup target must acquire the existing global `execution.lock`
and the candidate `cache.lock` nonblocking. Candidates are exact direct
`cache-[0-9a-f]{64}` children of a verified owned 0700 state directory. Require
the exact marker schema/key, `clean=true`, matching last-run UUID and receipt
SHA256. Additionally verify the receipt names this exact cache key/output base,
reports empty descendants, and the recorded supervisor PID/start time no longer
identifies a live process. Recheck the recorded dedicated cgroup as absent or
unpopulated. Unknown process visibility, identity or cleanup means skip.

Delete only the candidate's `output-base` subtree through directory descriptors
and `O_NOFOLLOW`; retain `owner.json` and `cache.lock`. Preflight every entry for
expected ownership, same device and bounded inventory; unlink symlinks without
following them. Refuse mount crossings, special files and unexpected ownership.
Use finite candidate, entry, depth and elapsed-time budgets. Do not invoke broad
`rm`, follow symlinks, signal unrelated processes or infer ownership from names.
If a budget expires after partial removal, mark the cache explicitly unavailable
and preserve a partial-prune receipt; no automatic reuse or recovery follows.

Write an exclusive, fsynced pruning receipt outside the removed subtree with
authority, exact key/path, prior cleanup receipt hash, evidence inventory hashes,
actor identity, inspected live-state results, bounded counts and outcome. A dirty
or unknown cache is retained for explicit owned-process inspection and recovery.
Pruning remains unimplemented and unexecuted.

Source-only follow-on adds `tools/guard_test_evidence.py` and its pure fixture
test. The helper copies selected exact labels' `test.log`, `test.xml` and
`test.outputs_manifest` metadata into the private UUID run directory before
cache reuse. It preserves Bazel's exact return status and reports missing,
stale, unsupported, refused or over-budget evidence explicitly. Epoch admission
time fences stale files; copies have digests and exclusive 0600 creation.
The budgets are 64 MiB/256 copied files, 64 labels and 32 configurations.
The guard now captures evidence after verified descendant cleanup and before
cache-clean admission; it records original workload status separately and refuses
reuse after preservation failures. Integration is source-only and unexecuted;
no evidence-copy PASS is claimed.

## Site-input source integration

After reported `d783` completion, source integration extended the fixed
public-input selection in `tools/execution_guard.py` to these four:

- `flake.nix`
- `flake.lock`
- `tools/offline-site-roots.json`
- `tools/tool-selection.nix`

Retain exact resolved sibling selection, nofollow regular public-file validation
and the 1 MiB per-file bound. The existing separate site path/digest cache binding
and receipt map then include the fourth digest automatically. Update the pure
fixture and expected input set. Verify the declared `@omux_site_inputs` producer
watches/exports the fourth file; do not widen runtime private-path selection or
add the sibling path to immutable-tool inputs. Old cache keys and evidence remain
historical. Root retains both producer keys; no pruning occurred. A separate
explicit site-inventory selector now accepts only the owned execution-state
cache's declared `cached_site_inventory_probe` output, with nofollow ownership
checks, an 8 MiB bound and an exact supplied SHA256. Its path/digest are separate
cache and receipt bindings, not immutable-tool inputs.
