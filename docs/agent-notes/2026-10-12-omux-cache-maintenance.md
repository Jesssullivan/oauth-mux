# R-C618 Omux execution-cache maintenance — 2026-10-12

Authority: explicit operator R-C618/R-C620; repository AGENTS.md; R-N11/R-N12/R-N13. This is an engineering checkpoint, not an operator ruling or a product release.

## Finished cleanup

The administrative passes directly removed **86,605,957 entries** from qualified finished Omux execution roots. They observed 86,605,951 last-link inodes and 202,049,421,312 allocated bytes. Observed allocation is not a physical-space recovery measurement. Filesystem net changes include concurrent actors.

The main pass pruned 288 finished runs, excluding one live-use/ownership case before mutation. Additional qualified passes cleared two user-root caches and the disposable directories of three subsequent finished model runs. Every owned mutation retained and read back receipt.json, supervisor.json, test-evidence* and workload.log. No service signals, provider calls, vault operations or source deletion occurred.

Four selected producer output roots and two separately recorded legacy output roots disappeared outside this coordinator's mutation set. Receipts survive; matching physical inputs require fresh producer qualification. Current Yoga selection still references the absent cache-v2-39f2eb3… output. The held sealed SDK and genuine N10 source roots ab09d29e and c188ba31 remained at readback; only their user-root caches were pruned. Unqualified roots were never made disposable solely by age.

## Prevention and actual proof

[execution_guard.py](../../tools/execution_guard.py) automatically selects one private ordinary-check namespace per canonical checkout in the configured state root for **exactly twelve named standard:test labels**. Explicit subsets reuse the same base across source changes. Its existing lease protocol binds locked tools, containment and policy; mismatches refuse reuse until explicit operator invalidation. Batch execution and uncached TEST results remain mandatory. This bounds namespace proliferation, not all internal cache bytes.

Reserved/native/SDK/source-producing lanes retain their fresh-output obligations. Shared ordinary outputs confer no historical native payload proof. Each invocation retains private receipts and copied test evidence; disposable per-run user roots retire afterward under the existing finite deadline and physical metadata fences.

V2 retirement passed 130 models but was too slow on large trees. The attempted V3 event-notification optimization was rejected by two independent reviews because silent mmap writes and mount overlays could evade its substituted checks. It was never adopted. V4.1 reused the existing cache lease and preserved the full V2 retirement fences; both complete source reviews cleared it.

Actual first run GC-1114 at source **6c69467c90035af5488de8a129166f053ea83622**, epoch eb6f9644-3f4f-4b0c-903f-f3db6c20eca9, passed **142 guard methods and docs**. It retained the shared base, removed its user-root directory completely, and published a clean digest-bound lease marker.

Actual second run OR-1118 at source **147a2bca0cb2db2e6a619bd8461eae2606bfc09b**, epoch fc520d99-0a7d-45cc-8403-1e763e073b4f, changed both source and target subset. It reused the same device/inode and locked-tool fingerprint, captured fresh per-epoch results, preserved the first run's original receipt/evidence digests, and completely removed its own user-root directory. Both original supervisors closed; no project executor remains.

The configured singleton is ordinary-check-v1-e73b8ee8d5549a0f26eaec8c4e0192cdf3f09c365b7da698c71d809beebbbda2/output-base under the integrated execution allocation. It is intentional working cache, not an unqualified retained native proof tree.

## Runtime outcome and next work

Reviewed compiler and sentinel-allocation repairs closed the original build errors and signedfixture abort. The signed fixture passed all 11 methods at b377972d. A strict locked-vault fixture correction preserves custody refusals and tests the already implemented redacted unknown/null diagnostics; production was unchanged.

OR-1118 compiled all five targets; format/docs passed. Runtime outcomes remain failed: Engine398/399, unit457/460, browser-attempt407/408. These overlapping suites are not unique-test totals. The common SIWC fixture serializes an empty tuple as params:[] and reaches InvalidParams before its intended WrongChannel assertions. Two additional unit failures involve UnknownLease in durable accepted-work reporting and preacceptance recovery. Their cause is not yet established; preserve the original failures and investigate without weakening no-replay authority.

No new installed, live-provider, ordinary accepted-history resume, same-process handoff, unmodified-Codex or Darwin support was proved. No achieved SLO or contractual SLA is created. The original fifteen-hour integrated objective remains active and incomplete, with its clock and scope unchanged.

## Durable joins

Full administrative records, copied failed logs and exact model receipts are under /home/jess/.local/state/omux-proposals-20261010/root/docs/agent-notes/.

- Final administrative totals: 2026-10-12-R-C618-final-administrative-totals.json.
- Two-run proof: 2026-10-12-R-C618-ordinary-cache-two-run-proof.json, SHA256 3eea7bc5607da24a2b0ee02861f9b1a9ee81cdfa2336168064e5ab60be12a71d.
- GC-1114 raw receipt: 4c3b7cbf9d858f17b3f7a83b967fe0c314677b93492eba1566fe10980d18b239; test manifest a720898979da118295e8a994902aaeb5169661f9692c57d26f337f34502f79f2.
- OR-1118 raw receipt: 644f16f73d77cf7e69f9d2a7c0757eb4b1aa4b9c9dd30eb6c1e39b02de0ec317; test manifest 4a2f55c8bfe4bd9eaf90fe387051eee897b9e3fa24fcf1e8ff6cfdce8a0f5d01.
- [TIN-2063](https://linear.app/tinyland/issue/TIN-2063): operator parent 51bcdc94-62f4-4097-9f22-f79073e5be73; owned factual reply a3c4b226-198d-4bac-843d-dabb917a9519.
- [TIN-5338](https://linear.app/tinyland/issue/TIN-5338): operator parent 0b47b272-d201-4fbe-bdb7-10aa5741181b.
- [Runtime draft #541](https://github.com/Jesssullivan/oauth-mux/pull/541): owned nonforce-pushed unsigned source, unmerged. Earlier passing receipts and failures retain their exact source scopes.
